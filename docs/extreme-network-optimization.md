# 极端网络环境分析与改进方向

> 基于 HEAD `7454d5c` 的代码审计。分析目标：突发大量请求与大量建连、80% 丢包、80% RST、
> 长期龟速连接等极端场景下，nextppp 作为纯应用层代理的表现边界与改进空间。
>
> 结论先行：**"脏但连通"的网络下现状尚可；极端场景下存在 4 个硬伤。其中大部分可以在纯
> 应用层修复，唯独"80% 丢包下的单流吞吐"受 TCP 拥塞控制数学限制，应用层只能绕开（换
> UDP 承载），不能修复。**

代码索引格式为 `文件:行号`，均基于上述 commit。

---

## 1. 现状：已经做对的部分

| 场景 | 现状 |
|---|---|
| 中途 RST / EOF | `crates/common/src/pump.rs:59-70` 把 reset/broken-pipe/timeout 归类为 routine close；`kill_session`（`pump.rs:385-388`）双向 shutdown 唤醒 sibling pump，干净拆除 |
| 突发 accept 资源耗尽 | `pump.rs:146-159` EMFILE/ENFILE/WSAENOBUFS 退避 100ms；slowloris 有 `handshake_timeout=15s`（`crates/common/src/config.rs:249-251`）+ `max_connections` 门槛（`crates/server/src/lib.rs:133-139`） |
| 半关闭传播 | `FRAME_EOF` + `Shutdown::Write`（`pump.rs:247-311`，协议定义 `crates/common/src/proto.rs:18-25`） |
| 背压 | pump 是锁步模型，慢对端天然反压到本地应用，内存不会无限涨 |
| 握手 dummy 包洪泛 | `read_session_id` 有 `max_nop_packets` 预算（`crates/core/src/transmission.rs:670-681`） |

## 2. 极端场景推演（按严重程度排序）

### 2.1 死连接永久泄漏（最严重）

数据面显式清零所有超时（`crates/client/src/outbound.rs:66-69`、`crates/server/src/lib.rs:268-270`），
且没有任何 TCP keepalive 或应用层 ping（全仓库无 `keepalive`/`socket2`）。后果：

- 对端 NAT 超时 / 断电 / 路径静默黑洞（无 FIN/RST）→ 两端各 2 个线程 + fd + scratch
  （plaintext 模式每隧道 ~450KB，见 `crates/core/src/transmission.rs:137-139, 270-272`，
  每方向峰值 131KB）**永久阻塞在 read()，直到进程重启**。
- 龟速连接同理：`write_all` 无超时，一个 stall 的对端钉死一对线程，通过
  `max_connections` 门槛逐渐挤占容量，最终拒绝新连接。

### 2.2 80% 丢包：建连成功率与吞吐双坍塌

- **握手**：全程约 6-8 个包交换（TCP SYN/ACK + NOP 1-3 帧 + sid + ivv + nmux + request +
  STATUS），每个包平均需 5 次发送才送达。默认 `connect_timeout=10s` 内大概率握不完 →
  `tunnel_connect` 失败 → SOCKS5 直接回 GENERAL FAILURE（`crates/client/src/socks5.rs:121`），
  **无重试**。
- **吞吐**：单 TCP 连接受 Mathis 公式约束 `≈ MSS/RTT × 1.22/√p`，p=0.8、RTT=100ms 时
  稳态上限仅 ~20KB/s，实际 RTO 主导更差。这是内核拥塞控制的数学，应用层改不了。
- **放大器**：默认 `plaintext=true`（`crates/core/src/config.rs:62`）意味着握手后**永久
  base94 外壳**，平均线上字节 ~1.64×（163/256 的字节值需双字符转义）。高丢包下等于再砍
  40% 有效吞吐。

### 2.3 突发大量建连（10k+）

- thread-per-connection：每条代理连接 client 2 线程（会话线程
  `crates/client/src/lib.rs:197-205` + down 泵 `pump.rs:419-425`）+ server 2 线程
  （`crates/server/src/lib.rs:147-153` + down 泵），栈各 256KB（`SESSION_STACK
  server/lib.rs:40`、`PUMP_STACK pump.rs:42`）。10k 并发 ≈ 4 万线程、GB 级内存，
  阻塞线程模型到这个量级是结构性上限。
- 每次 SOCKS CONNECT = 新 TCP + 完整握手 + request/reply ≈ 3 RTT 建连税。**mux 协商位
  在协议里已存在（`transmission.rs:597`、`:633-637`）但 server 永远传 `false`
  （`server/lib.rs:228`），从未启用**。
- server 端每次 connect 都 `getaddrinfo`（`pump.rs:176-225`），无缓存，突发同域连接堆积
  resolver 线程（glibc 内部 ~10s 才放弃）。
- std 的 listen backlog 固定 128（`crates/nextppp/src/main.rs:92`），SYN 突发下是第一道瓶颈。

### 2.4 80% RST

- 建连被 RST → 无重试直接失败（前端 sing-box 可能重试，但带自己的退避节奏，慢）。
- **单端口暴露**：定向 RST 攻击打一个端口就全灭，没有 port hopping。
- 扫描/探针风暴：每个探针消耗一个线程 + 15s 握手等待，`handshake_failures` 有计数
  （`server/lib.rs:185`）但无节流。

---

## 3. 改进方向

分组：A = 纯应用层小工作量（建议全做）；B = 纯应用层中等工作量（性能上限的大头）；
C = 换承载。

### A1. Keepalive / 死连接回收 —— 修线程泄漏

**现状缺口**

- 数据面显式清零全部超时：`crates/client/src/outbound.rs:66-69`、
  `crates/server/src/lib.rs:268-271`（注释原话 "Data plane: no timeouts"）。
- 之后 4 个线程中任何一个都可能永远阻塞：up 泵阻塞在 `local.read()`
  （`crates/common/src/pump.rs:247`），down 泵阻塞在 `rx.read_buf()`（`pump.rs:284`）。
  对端 NAT 静默超时 / 路径黑洞时，唯一能唤醒它们的是对端主动关流——死路径永远等不来。
  `kill_session`（`pump.rs:385-388`）只在本端先出错时才触发，帮不了"对端蒸发了"的场景。
- 全仓库没有任何 TCP keepalive 或应用层心跳。

**改法（两层，可同时做）**

1. **内核 TCP keepalive**：在 `pump::tcp_connect` 连接成功后（`pump.rs:217-219` 附近）
   和 client 的 inbound stream 上（`crates/client/src/socks5.rs:44-48`）用
   `socket2::TcpStream::set_tcp_keepalive` 设置 `time(60s) / interval(15s) / retries(3)`。
   约 100 行内搞定全平台（Windows 不支持自定义 retries，走系统默认）。read 阻塞中的线程
   会因 keepalive 探测失败收到 RST/ETIMEDOUT 而解除阻塞，随后现有的 `classify_io`
   （`pump.rs:115-120`）自动把 `TimedOut` 归为 routine close，日志路径无需改动。
2. **应用层 `FRAME_PING`**（可选补充）：在 `crates/common/src/proto.rs:18-25` 加一个
   tag，泵在空闲 N 秒后发送。好处是不依赖 OS 参数、粒度可控；坏处要给泵加定时器
   （std 阻塞 I/O 下需要一个带 `read_timeout` 的轮询循环，`pump.rs:243-268` 的简单循环
   会变复杂）。

**优先做 1**。keepalive 探测包是内核生成的纯 ACK，无负载，不产生新的 DPI 指纹。

- 收益：堵住最大的资源泄漏；`max_connections` 门槛不再被死会话慢性挤占。
- 代价：新增 socket2 依赖；几乎无风险。

### A2. 握手省 1 RTT（0-RTT request）

**现状缺口**

- 客户端握手序列（`crates/core/src/transmission.rs:579-615`）：发 ivv（`:591`）→
  **阻塞等 nmux**（`:593`）→ canary 校验（`:602-608`）→ rekey（`:610`）。之后才发
  connect request（`outbound.rs:55`）并等 STATUS（`outbound.rs:56`）。
- 但 rekey 材料就是客户端自己生成的 ivv（`transmission.rs:587`）——客户端根本不需要等
  服务端任何东西就能 rekey 并发数据。等待 nmux 只是为了：mux 奇偶位（当前服务端写死
  `false`，没用）和 canary 校验（只是校验，不依赖时序）。

**改法**

关键观察：**收发两个方向的核心状态本来就是独立的**（`TxCore`/`RxCore`，
`transmission.rs:128/263`），`on_handshake_complete` 也是逐方向调用的
（`transmission.rs:610-612`）。所以：

1. `handshake_client` 拆成两段：`send_session_id(ivv)` 之后立即 `tx.rekey(ivv)` +
   `tx.on_handshake_complete()`，返回给调用方一个"待确认"状态；
2. 调用方（`outbound.rs:55`）马上用 rekey 后的帧发 request（比现在早飞 1 个 RTT）；
3. 客户端收方向的 confirm（读 nmux、校验 canary、`rx.rekey` +
   `rx.on_handshake_complete()`）挂在**第一次 read 之前**执行——`outbound.rs:56` 读
   STATUS 前插入即可。
4. 服务端零改动：它本来就是先发 nmux 再读 ivv（`transmission.rs:627-640`），随后按新帧
   读 request（`server/lib.rs:237`），时序天然兼容。

线上字节序：client→server 方向是 `[NOP..][ivv][rekeyed request 帧]`，server→client 方向是
`[sid][nmux][rekeyed STATUS 帧]`，两个方向的旧/新帧不会交错，解码状态机不用动。

- 收益：CONNECT 关键路径 −1 RTT；80% 丢包下每省一个 RTT 都显著提升建连成功率。
- 代价/风险：canary 不匹配的报错时点推迟到首个 read（错误从 `handshake_client` 变成
  confirm 阶段，`FlagsMismatch` 语义不变）；API 面积 +1。协议不兼容原版，无历史包袱。

### A3. `tunnel_connect` 快速重试

**现状缺口**

- `outbound.rs:26-71` 一次连接失败（TCP RST / 握手超时）直接把错误抛给 `socks5.rs:102`
  的调用点 → 回 `REP_GENERAL`（`socks5.rs:121`），前端代理要靠自己的重试节奏，慢且不可控。

**改法**

- 重试循环包在 `tunnel_connect` 外层，**每次重试用全新 TcpStream**（幂等，无残留状态——
  所有会话状态都在 `Transmission::new` 里，`outbound.rs:47`）。
- 重试范围要区分：connect 阶段的 `ConnectionReset/TimedOut` → 重试；`FlagsMismatch`
  （配置错）→ 不重试；服务端 `STATUS_REFUSED`（目标真的拒了）→ 不重试。判定可复用
  `pump.rs:59-70` 的 `routine_cause`。
- **DNS 不要重做**：解析已含在 `pump::tcp_connect`（`pump.rs:179-207`）里，重试应只重
  connect 部分（`pump.rs:209-222`），否则每次重试多一个 resolver 线程
  （`pump.rs:183-192`）。实现上要么把重试下推进 `tcp_connect` 的地址循环（对每个地址
  试 2 次再换下一个），要么把 resolve 与 connect 拆开。
- 配置项 `connect_retries`（默认 1）加进 `ServerSection`
  （`crates/common/src/config.rs:232-243`）。

- 收益：RST 概率 p 时成功率 `1-(1-p)^n`：80% RST 下 1 次重试 = 20%→36%，接近翻倍。
- 代价：高丢包链路上 SYN 翻倍（TCP 本身也在重传，无碍）；**对抗环境下重试会放大
  censor 可见的连接尝试频率**——所以做成配置项而非硬编码。

### A4. 默认/指引 `plaintext=false` + CTR/ChaCha20

**现状缺口（两个放大器）**

1. **线上字节膨胀**：默认 `plaintext: true`（`crates/core/src/config.rs:62`）意味着
   握手后永远保留 base94 外壳（分支在 `transmission.rs:188` 和 `:352`）。base94 编码中
   163/256 ≈ 64% 的字节值要双字符转义，期望膨胀 ~1.64×。丢包率 p 固定时，goodput 直接
   除以 1.64，重传的字节也 ×1.64。
2. **CFB 串行链**：默认 `transport: Aes256Cfb`（`config.rs:59`）。core README §5.3 已
   自述：CFB 加密方向是串行反馈链（≈3 c/B），而 **server 下行（大流量方向）恰好走
   加密**；且 TCP 重传会放大重复加密工作量。`aes-256-ctr`/`chacha20-ietf` 全并行
   （`Method` 枚举 `crates/core/src/crypto/cipher.rs:59-65`）。

**改法**

- 改默认值是**破坏性变更**（binary 与 base94 帧线上互不兼容，`transmission.rs:188/352`
  二选一），且两端必须同步改——好在 canary 覆盖 `plaintext` 位
  （`crates/core/src/handshake.rs:45-52`），不一致会显式 `FlagsMismatch` 而不是静默烂掉。
- 稳妥路径：默认不动，做三件事——README/示例配置（`crates/nextppp/examples/`）加高丢包
  场景推荐段；启动时若检测到 `plaintext=true && transport=*cfb` 打一条 `info` 建议；
  文档写清切换是两端同步操作。
- 激进路径：直接改默认（项目还在 0.1.x，语义化版本允许）。

**权衡要说透**：`plaintext=true` 的意义是**整条流**保持可打印 ASCII（伪装成文本协议），
DPI 面前比"握手后变随机字节"更抗指纹。注意握手阶段**永远**是 base94（`!handshaked`
强制，`transmission.rs:188`），所以 `plaintext=false` 只是让"握手后的数据面"从可打印
变为随机字节——和 TLS/SSH 一致的特征。这是抗封锁 vs 吞吐的显式取舍，应交给部署者。

### A5. listen backlog 128→4096 + `TCP_DEFER_ACCEPT`

**现状缺口**

- `crates/nextppp/src/main.rs:92` 用 std 的 `TcpListener::bind`，内核 backlog 硬编码
  128。SYN 突发 / 大量建连时 accept 队列溢出，内核直接丢 SYN 或回 RST，客户端表现为
  建连失败——这是突发建连场景的**第一道**瓶颈，比线程模型更早触发。

**改法**

- `bind_listen` 改用 socket2：`Socket::new → bind → listen(4096) → TcpListener::from`。
- Linux 上加 `TCP_DEFER_ACCEPT`：accept 只在首包数据到达时返回。对本协议是**纯赚**：
  客户端连上后立刻发 NOP 前奏（`transmission.rs:580`，client 是先说话的一方），合法连接
  的 accept 时点几乎不变；而**从不发数据的纯端口扫描器永远不会唤醒 accept**，每个探针
  省一整个握手线程 + 15s 超时（`server/lib.rs:223-224`）。socket2 若未暴露该选项，用
  一个极小的 `libc::setsockopt`（注意 `pump.rs:146-154` 的注释：libc 目前只是
  dev-dependency，需转正）。
- Windows 无此概念，跳过（WSAENOBUFS 已由 `accept_backoff` 兜底，`pump.rs:152`）。

- 收益：突发建连容量 ×32；探针风暴的线程成本归零（配合 A7 效果叠加）。
- 代价：新增依赖/一行 unsafe；行为差异需在 e2e 里验证（DEFER_ACCEPT 下 accept 语义变化
  不影响现有测试，因为测试客户端总是先发数据）。

### A6. 服务端 DNS 缓存（TTL）

**现状缺口**

- 每个会话独立解析目标域名：`server/lib.rs:259` → `pump::tcp_connect` → 每次连一个
  resolver 线程跑 `getaddrinfo`（`pump.rs:183-192`）。突发 1000 个同域 CONNECT = 1000
  个 getaddrinfo 并发；glibc 解析器在坏网络下挂 10s+，线程和 fd 消耗线性堆积（设计注释
  自己承认这点，`pump.rs:163-169`）。
- client 侧同样：`ClientRuntime.server_host` 保留域名形态
  （`crates/client/src/lib.rs:100-105`），**每条** SOCKS CONNECT 都重新解析服务器域名
  （`outbound.rs:28`）。

**改法**

- 简单版（推荐先做）：`HashMap<String, (Vec<SocketAddr>, Instant)>` + `RwLock`，正
  TTL 300s / 负 TTL 30s，容量上限 + 简单 LRU 淘汰。手写 ~100 行，不必引第三方。
- 挂载点：`ServerRuntime` 持有 cache 实例，`pump::tcp_connect` 加一个 resolver 参数
  （或抽个 `Resolve` trait 让测试注入）。
- 失败语义优化：解析超时时回吐**过期缓存**（stale-while-error）比直接失败好——丢包环境
  下 DNS 往往是第一个阵亡的，旧地址大概率仍有效。

- 收益：热域名解析成本归零；resolver 线程不再随突发建连线性增长；丢包下 DNS 这类前置
  依赖的脆弱性被缓存兜底。
- 代价：目标 IP 变更有最长 TTL 延迟（对代理场景可接受）；锁竞争在万级 QPS 下才需要考虑
  （那时换 `moka`/`quick_cache`）。

### A7. 探针节流（per-IP 冷却 + 握手失败限流）

**现状缺口**

- 每个到达的连接都无差别 spawn 一个会话线程（`server/lib.rs:147-153`），失败路径只计数
  + warn（`server/lib.rs:229-234`），`handshake_timeout` 15s（`config.rs:249-251`）。
  扫描器 10k conn/s 打过来：10k 线程 × 15s 生命周期，`max_connections` 门槛统计的是
  active（含握手中的），很快被探针占满，**合法用户被探针挤下线**；同时 warn 日志洪水
  （`:233`）。

**改法（三选一或组合，按实现成本排序）**

1. **握手并发信号量**（最简单）：与 `max_connections` 分开，单独限制"握手中"数量
   （如 256）。到达上限的连接直接关闭——探针与突发合法建连共享这个池，但探针不消耗
   15s 全程就是被即刻断掉。
2. **per-IP 失败冷却**：`HashMap<IpAddr, (失败计数, 窗口起点)>`，30s 内失败 ≥5 次的 IP
   进 60s 黑名单，在 accept 循环里（`server/lib.rs:122-146`）提前 `continue`。注意内存
   上限（IP 数量有限，用 LRU 或定期清理）。
3. **warn 限频**：失败日志改成每 N 条打 1 条 + 计数（配合 heartbeat 已经有的
   `handshake_failures` 字段，`server/lib.rs:185`）。

- 收益：探针从"每连接一线程"降为"每 IP 一条表项"；`max_connections` 预算留给真实流量。
- 代价/风险：小心别把 NAT 后面的大量合法用户误伤（共享出口 IP）——阈值放宽 + 只冷却
  "握手失败"而不是"连接数"；黑名单决策要在 accept 循环里保持 O(1)。

---

### B8. Mux 连接池 —— 根治突发建连

**协议里已有的钩子（最顺理成章的一项）**

- mux 协商位已存在：`nmux` 奇偶（`transmission.rs:597` 客户端解出，`:633-637` 服务端
  置位），但服务端写死 `false`（`server/lib.rs:228`）。
- **内存编解码路径就是为此设计的**：`encrypt_into`/`decrypt`/`decrypt_in_place`
  （`transmission.rs:527-548`、`TxCore::encrypt_into :161`、`RxCore::decrypt_in_place
  :323`），doc 注释明说 "for datagram / mux style callers"（`transmission.rs:22-23`）。
  零拷贝、不触碰传输层。

**设计草图**

- **client 侧**：维护 K 条（4-8）长活隧道到 server，保持热备（空闲时由 A1 的 keepalive
  保活；低于 K 条时后台补连）。每条 SOCKS CONNECT（`socks5.rs:102`）不再新建隧道，而是
  在负载最低的池隧道上开一个 **stream id**（varint），发 `FRAME_OPEN(stream_id,
  ProxyAddr)`——即扩展 `crates/common/src/proto.rs:18-25` 的 tag 集合为 per-stream 的
  OPEN/DATA/EOF/CLOSE。此后该 SOCKS 会话的 pump 直接复用 `write_tagged`
  （`transmission.rs:730`）加 stream 前缀。
- **server 侧**：每条隧道一个分发线程：读帧 → 按 stream id 查注册表 → 转给该 stream 的
  目标泵（目标连接的 pump 模型不变，只是"隧道端"从整条 `Transmission` 换成注册表里的
  一个发送句柄）。`server/lib.rs:199-294` 的 `handle_conn` 需要重构为 `handle_tunnel`
  （分发器）+ `handle_stream`（每流）。
- **HOL 缓解**：单条 TCP 内丢包会**联坐所有 stream**（队头阻塞）——80% 丢包下这是真
  问题。对策：K 条隧道做 least-loaded 分摊，单条隧道 stall 不拖垮全部；stream 数上限
  （如每隧道 64）触发时开新隧道。**必须做成可配置 + 可关闭**，因为 mux 是"突发建连
  扩展性 ↑、丢包隔离性 ↓"的交换，不是无条件赢。

**收益量化（对比现状）**

| | 现状 | mux 池 |
|---|---|---|
| 1000 并发 CONNECT 的握手 | 1000 × (TCP SYN + 6-8 包 + 2-3 RTT) | 8 次摊销，per-CONNECT ≈ 0 RTT |
| 线程 | client 2000 + server 2000（`socks5.rs:112` + `pump.rs:419-425` 各拆两半） | 池 8×2 + 每目标流泵 |
| 内存 | 每隧道 ~450KB plaintext scratch（`transmission.rs:137-139, 270-272`，每方向峰值 131KB，`BASE94_MAX_FRAME`，`crates/core/src/frame/base94.rs:90`） | 池隧道独占 scratch，流共享 |
| 80% 丢包建连成功率 | 随每 CONNECT 独立掷骰 | 握手失败风险集中在 K 条上，重连成本由池吸收 |

### B9. 结构性并发改造（thread-per-conn → 事件驱动）

**现状缺口**

- 每代理连接 = client 2 线程（会话线程 `crates/client/src/lib.rs:197-205` + down 泵
  `pump.rs:419-425`）+ server 2 线程（`server/lib.rs:147-153` + down 泵）。栈 256KB×2 +
  scratch 常驻。10k 会话 ≈ 4 万线程、GB 级内存，撞 Linux `threads-max`/
  `vm.max_map_count` 和调度器上限。阻塞模型的正确性没问题（`kill_session` 的唤醒协议
  很干净，`pump.rs:379-388` 注释写得很清楚），是**容量**问题。

**改造路径（成本递增）**

1. **mio/polling + 固定 worker 池**：pump 循环（`pump.rs:243-268/:281-316`）改非阻塞
   状态机。编解码核心 `TxCore`/`RxCore` 不含 I/O（参数式传入 io，
   `transmission.rs:221/:350`），可原样复用。
2. **tokio/async**：`Transmission` 的流式 API 是同步 trait（`Read+Write`，
   `transmission.rs:552`），不能直接用；但 `encrypt_into`/`decrypt_in_place` 是纯内存
   的——async 层只需要一个 buffer 桥（读到完整帧 → `decrypt_in_place` → 分发）。等于
   重写 I/O 外壳、保留全部协议状态机。
3. **io_uring**（Linux）：多路复用 + 减少系统调用，配合 `transmission.rs:29-35` 注释里
   已有的"2 syscall/帧"考量。

**优先级建议**：排在 B8 之后。mux 落地后每隧道才 2 线程、流是纯内存状态，线程数已经
下降一个数量级，事件驱动的紧迫性大幅降低。

---

### C10. UDP 承载（KCP/Hysteria 风格 ARQ+FEC）

**为什么这是 80% 丢包下唯一的"恢复正常水平"路径**：单 TCP 吞吐受 Mathis 公式
`≈ MSS/RTT × C/√p` 约束，p=0.8 时数学上就是 KB/s 级，且丢包被拥塞控制误读为拥塞而加倍
降窗。UDP + 用户态 ARQ（选择性重传）+ FEC（前向纠错）+ 固定/激进速率（Hysteria 的
brutal 思路）完全绕开这套逻辑——丢 80% 就按 5× 冗余发，不降速、不进 RTO 黑洞。

**架构上已铺好的路**

- `Transmission<T>` 泛型与 I/O 解耦（`transmission.rs:456`）；`TxCore`/`RxCore`
  （`:128/:263`）不触碰传输层。
- 内存路径 `encrypt_into`/`decrypt_in_place`（`:527/:540`，零分配版 `:783-791`）把
  "一个 nextppp 包 ↔ 一个 UDP datagram"变成直接组装：`encrypt_into → send_to`，
  `recv_from → decrypt_in_place`。

**需要新建的层（诚实的工作量清单）**

1. **可靠性层**：seq/ack、选择性重传、RTT 估计；FEC（如 `reed-solomon-erasure`）。
2. **MTU 分片重组**：wire 包最大 131136（`base94.rs:90`），UDP datagram 必须 ≤~1200B——
   `encrypt_into` 的输出要切块。注意 base94 膨胀 1.64× 在这里再次恶化有效载荷（1200B
   datagram 只装 ~730B 明文），是 binary framing（A4）的又一个论据。
3. **会话映射**：UDP socket 无连接状态，需要 session id → 对端五元组的注册表 + 超时
   回收；握手包（session-id 包，`crates/core/src/handshake.rs:75-180`）本身要加重传
   逻辑。
4. **反指纹**：UDP datagram 长度对外可见，需要随机 padding/尺寸（复用 `handshake.rs`
   已有的 padding 思路）；纯可打印 ASCII 的 UDP 流本身罕见，伪装策略要重新评估。

**定位**：三项里工作量最大（可靠性层 + 分片 ≈ 一个新传输后端），但编解码核心 100%
复用意味着省掉协议部分——大约是"新写 60%"而不是"从头来"。

---

## 4. 依赖关系与建议顺序

```
A1 (keepalive) ──────────────┐
A5 (backlog/DEFER_ACCEPT)    ├─→ 各自独立，先做
A6 (DNS cache)               │
A7 (探针节流) ────────────────┘
A2 (0-RTT) ──→ A3 (重试)     └─→ B8 (mux 池) 依赖 A1 保活；依赖 A2 的收发独立化经验
A4 (binary framing) 独立，但 B8/C10 都受益于它
B9 排在 B8 之后；C10 独立长期项
```

一句话收束：A 组六项都是几十到几百行的修补，其中 **A1 是可靠性缺口、A5+A7 是抗探测/
突发缺口、A2+A3 是高丢包建连缺口、A4 是吞吐乘数**；B8 是扩展性的根治；C10 是丢包吞吐
的根治——而"不侵入连接层就无法优化"的边界正好处在 B8 与 C10 之间：TCP 上的所有应用层
优化（含 mux）都能改善**建连与资源**维度，唯独**单流丢包吞吐**必须换 UDP 承载。

## 5. 后续：把极端网络变成可量化回归

建议增加 `tc netem`（delay/loss/reset/corrupt 注入）的 e2e CI job，把"极端网络下工作到
正常水平"变成指标而非感觉：

- 建连成功率（按 loss/RST 参数矩阵）
- 握手耗时 P50/P99
- goodput（固定文件大小 / 固定时间窗）
- 僵尸会话数（断网后 N 分钟内是否归零，验证 A1）

---

*行号基于 `7454d5c`（2026-08-25），后续提交可能漂移；以符号名搜索为准。*
