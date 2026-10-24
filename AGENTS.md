---
description: coding
mode: primary
temperature: 0
---

# 项目要求

这是一个 Rust 代理服务端 + 客户端，用于 bypass GFW 检测与拦截。协议魔改自 [openppp2](./docs/openppp2-algo.md) 。

核心要点：

1. openppp2 使用自研协议，且该协议 bypass GFW 能力已经过广泛验证。当前 nextppp 协议**不与原版兼容**，但是保留了 bypass GFW 而进行的特殊设计。目前已经实现完成，详见 `crates/core/README.md`。
2. 原版 openppp2 是工作在虚拟网卡上的 VPN，而本次重写目标是做一个应用层代理工具而非 VPN，不涉及网卡等底层内容。
3. client 定位为纯粹的"本地 SOCKS5 -> nextppp 隧道"转发器：不内置规则引擎、HTTP 入站、direct/block、系统代理设置。分流（规则 / geosite / geoip / 系统代理）交给 sing-box 等成熟前端，把 nextppp 的 socks5 入站作为其 outbound 使用。
4. server 与 client 构建为同一个 binary（`nextppp`，clap 子命令区分角色）：协议核心本就共享，单 artifact 便于分发且两端版本一致。角色逻辑保留在 `crates/{server,client}` lib crate 中（e2e 测试依赖），`crates/nextppp` 只是 CLI 胶水层。

其他规范：

1. 性能优先，关键路径需要 simd。
2. 代理实现必须跨 Windows/Linux/Macos 多平台。
