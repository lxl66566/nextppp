# 优化批次 2 实施进度

> 依据 `docs/extreme-network-optimization.md` 执行：本批次做 A4（默认值切换）、
> B8（mux 连接池）、B9（事件驱动）；C10（UDP 承载）明确不做。
> 协议不做旧版本兼容（用户明确要求激进改造）。验收：新增逻辑有测试覆盖，
> `cargo fmt` / `cargo clippy --workspace --all-targets [--features hotpath]` /
> `cargo test --workspace`（124 用例）全绿。

## 提交序列与状态

| # | 条目 | 来源 | 提交 |
|---|------|------|------|
| 1 | A4 默认 `plaintext=false` + `transport=aes-256-ctr` | §A4 | `perf(core)!` |
| 2 | core `Session`：transport-free 增量帧解码 | B9 前置 | `feat(core)!` |
| 3 | common mux 线协议 v2（kind + varint stream id + payload） | §B8 | `feat(common)!` |
| 4 | core `Session::split`（tx/rx 半边，reader/writer 任务分离） | B9 前置 | `feat(core)` |
| 5 | common 异步隧道驱动（run_writer 批量写、FrameReader 增量重组） | §B9 | `feat(common)` |
| 6 | client/server tokio 重写 + mux 连接池 | §B8/§B9 | `refactor!` |
| 7 | 修复：stream pump 拆双方向独立任务（死锁） | 回归 | `fix(common)` |
| 8 | README 基准数据 + 本文档 | — | 本次 |

## 实施要点与经验

- **A4**：binary 帧消除 base94 ~1.64× 线上字节膨胀；CTR 替换 CFB 串行反馈链
  （≈3 c/B）。canary 覆盖两个字段，两端不一致显式 `FlagsMismatch`。
  附带发现一个存量语义：binary 路径下失败的 `decrypt` 会消耗 rx cipher 状态
  （必须解密帧头才能拿到长度），`truncated_packet_rejected_in_memory` 测试调整为
  先验成功后验失败，并在注释记录该语义。
- **Session（B9 的关键前置）**：`TxCore`/`RxCore` 本就不含 I/O；新增
  `Session::poll_frame` 把"读到完整帧再解码"变成增量式（binary 头解密每帧恰好
  一次，跨 feed 缓存 `(len, header_kf)`；base94 头明文可直接 peek 长度）。握手仍走
  同步 `Transmission`（spawn_blocking，带超时），握手后 `into_session()` 切到异步
  数据面——握手状态机零重写、零重复。
- **mux 协议 v2**：`[kind][stream_id varint][payload]`，OPEN/REPLY/DATA/EOF/CLOSE
  五种帧；只有 client 能 OPEN，stream id 单计数器即可。REPLY 复用 v1 的 STATUS。
- **连接池**：默认 4 条热备隧道、least-loaded 分配、每隧道 64 stream 上限；
  后台 maintainer 保活补连。**两个并发教训**：
  1. maintainer 只数 live 隧道不数 in-flight dial，拨号在轮次中间完成会超额补连
     （2 条拨出 3 条）——加 `dialing` 原子计数修复；
  2. `Notify::notify_waiters` 不存 permit，隧道死亡发生在 maintainer 两次循环之间
     会丢失通知、补连停滞 30s——改用存 permit 的 `notify_one`。
- **B9 结构**：accept → spawn_blocking 握手（probe 闸 `max_handshakes` 不变）→
  `into_session` → 每隧道 1 writer 任务（try_recv 批量合写）+ 1 demux 循环；每
  stream 1 个 pump（内含 2 个方向任务）。server 端 OPEN 注册表 `Arc<Mutex<HashMap>>`，
  锁内不做 await。
- **死锁回归（最重要的一次失败）**：初版 stream pump 是单任务 `select!`，任务阻塞在
  有界 channel 的 `send().await` 时无法排空入方向事件，两端背压形成环 → 256 MiB
  吞吐基准挂死。修复：恢复老泵的双方向独立任务结构（graceful EOF 留兄弟任务，
  其余终结 abort 之），字节计数放共享原子量避免 abort 丢失。注释已记录成因。
- **stream 生命周期**：EOF 双向走完 = Graceful（drop 不发 CLOSE）；其余路径 drop 时
  best-effort CLOSE；对端收到未知 stream 的帧回 CLOSE 防止注册表泄漏。半关闭语义与
  旧 `kill_session` 唤醒协议对齐。专用隧道（`mux.enabled=false`）随唯一 stream 终结。
- **e2e 新增证明**：8 并发 socks 连接共享 2 条隧道（mini server 握手计数 == 2）；
  隧道中途死亡 → 在飞 stream 失败且连接池自动补连恢复。mini mux server 是测试内
  独立同步实现，兼作线协议互操作证明。

## 基准（README 已同步）

AMD 7945HX、server/client 各限单核、默认配置（binary 帧 + aes-256-ctr）、
6 轮 256 MiB 单向：**165.22–177.18 MiB/s，中位 ≈171.6**。
对照上一版默认（base94 + aes-256-cfb + 线程模型）同机 165.76 MiB/s。
单流回环吞吐本就受单核 crypto 限制，本批次收益主要在并发建连与资源占用
（每连接线程数从 4 → 0，握手成本 ~0 RTT），单流数字持平略升为预期。
