# 优化批次 1 实施进度

> 依据 `docs/extreme-network-optimization.md` 的 A 组（纯应用层小工作量）条目执行；
> B 类（mux 连接池、事件驱动）与 C 类（UDP 承载）留待下一批次。
>
> 每个条目一次原子提交，提交后更新本表状态。验收：新增/修改的逻辑必须有测试覆盖，
> `cargo fmt` / `cargo clippy --all-targets` / `cargo test --workspace` 全绿。

## 工作顺序与状态

| # | 条目 | 来源 | 状态 | 提交 |
|---|------|------|------|------|
| 0 | 本进度文档 | — | ✅ | 本次 |
| 1 | A1 TCP keepalive：堵住死连接线程/fd 泄漏 | §A1 | ✅ | `perf(common)` |
| 2 | A5 listen backlog 4096 + `TCP_DEFER_ACCEPT`（Linux） | §A5 | ⬜ | |
| 3 | A6 DNS 缓存（正 TTL 300s / 负 TTL 30s / stale-while-error） | §A6 | ⬜ | |
| 4 | A2 握手 0-RTT：`handshake_client` 拆 send/confirm，request 提前 1 RTT | §A2 | ⬜ | |
| 5 | A3 `tunnel_connect` 快速重试（`connect_retries`，复用 A6 的缓存不重复解析） | §A3 | ⬜ | |
| 6 | A7 探针节流：握手并发上限 + 失败日志限频 | §A7 | ⬜ | |

排序理由：A1/A5 独立且最小，先落地；A6 先行使 A3 的重试不必重复跑 resolver；
A2 改握手时序，放在自己的提交里便于回归定位；A3 依赖 A2 后的新握手 API 语义；A7 收尾。

## 明确不做（本批次）

- A4（`plaintext=false` 默认值切换）：抗指纹 vs 吞吐是部署者取舍，只做文档/提示层面（见 A1 提交顺带
  评估，若收益明确再单列提交）。
- B8 mux 连接池、B9 事件驱动、C10 UDP 承载：下一批次。

## 实施日志

- **A1**：`pump::keepalive`（60s 空闲 / 15s 间隔 / 3 次探测，Windows 走系统默认重试）。挂载点：
  `tcp_connect` 两条成功路径（client→server 与 server→target 同时覆盖）、socks5 inbound、
  server accept 流。探测包为纯 ACK，不引入 DPI 指纹。测试：`keepalive_is_applied` 用
  socket2 getter 断言参数落核（Linux 全参数，其他平台断 SO_KEEPALIVE）。
  备注：clippy 的 `needless_pass_by_value`（pump.rs `tunnel_up/down`）为存量警告，本批次不动。
