# openppp3-core 实现说明

> 本文总结 `crates/core` 的 Rust 实现：模块结构、协议流程、以及与 openppp2 C++ 原版的主要区别。
> 协议算法细节见 `docs/openppp2-algo.md`（原版规范），本文只讲"新实现长什么样、改了什么"。

## 1. 定位

`openppp3-core` 是协议核心库：帧化、混淆、握手、会话密码，全部与 I/O 传输解耦。
它不关心 TCP/UDP/网卡，只提供两种使用方式：

- **流式**：`Transmission<T: Read + Write>` 直接包住任意双工字节流（TCP 等），提供
  `handshake_client` / `handshake_server` / `read` / `write`。
- **内存**：`encrypt_into` / `decrypt` 不触碰传输层，把明文编成一个完整线上包（或反向），
  供 datagram / mux 风格的上层使用。

## 2. 模块结构

| 模块 | 职责 | 对应原版 |
|------|------|----------|
| `config.rs` | `ObfuscationKey`：kf/kl/kh/kx、protocol/transport 密码、masked/plaintext/delta/shuffle 开关 | `AppConfiguration` 的 key 段 |
| `crypto/ssea.rs` | 混淆原语：31 位 LCG、shuffle/unshuffle、delta 编解码、masked XOR、base94 字节/整数编解码 | `ssea.cpp`（字节级兼容） |
| `crypto/cipher.rs` | `Method` 枚举 + `SessionCipher`：HKDF-SHA256 派生、每包 nonce 的流密码 | `EVP.cpp` / `rc4.cpp`（重写） |
| `frame/base94.rs` | base94 帧：首帧 7 字节扩展头（含校验和）、后续 4 字节简单头、奇偶性机制 | `ITransmission.cpp` §4 |
| `frame/binary.rs` | 二进制帧：3 字节加密头 + 负载变换链 | `ITransmission.cpp` §5 |
| `frame/checksum.rs` | RFC 1071 Internet checksum | `checksum.h` |
| `handshake.rs` | NOP 前奏、session-id 包、flag canary | `ITransmission.cpp` §7 |
| `transmission.rs` | 数据面调度 + 握手状态机 + `split_with` 半双工拆分 | `ITransmissionBridge` |
| `error.rs` | 类型化错误（thiserror） | 错误码宏 |

## 3. 协议流程（与原版一致的部分）

```
client: nop* ->          <- sid (server session id)
client:      ivv ->      <- nmux (mux parity + flag canary in high 64 bits)
both:   rekey ciphers from ivv, switch to data-plane framing
```

- 握手前（及 `plaintext=true` 时）所有线上流量为可打印 ASCII（base94 外壳）。
- 二进制帧头 3 字节：随机 seed 定义 `header_kf = kf ^ seed`，长度字段经 protocol 密码加密、
  XOR 掩码、shuffle、delta；负载经 transport 密码 + masked/shuffle/delta 变换（握手前强制全开）。
- 每连接由客户端随机 `ivv` 派生独立工作密钥，防多连接指纹关联。

## 4. 与原版的主要区别

### 4.1 密码学修正（安全）

| 原版 | 新版 | 原因 |
|------|------|------|
| `EVP_BytesToKey(MD5, 1 round)` + MD5 IV 搅动 + 自定义 RC4 再搅 IV | HKDF-SHA256（salt 含方法名） | MD5 系 KDF 过弱，RC4 搅动只算混淆不算安全 |
| 每包用**相同 key/IV** 重新初始化 EVP 上下文 → 全部包复用同一 keystream（two-time pad，`C1^C2 = P1^P2`） | TLS-1.3 风格：`nonce = base_iv XOR be64(seq)`，每方向单调 64 位计数器 | 修复 keystream 重用漏洞 |
| .NET 风格 56 槽减法生成器 | `StdRng::from_os_rng()`（CSPRNG） | 协议不依赖随机序列，只依赖分布，可安全替换 |
| 自定义 RC4-255 密码族（`rc4-md5` 等） | 删除；新增 AES-CTR / ChaCha20 | RC4 已破，新 KDF 不再需要它 |
| 密码名运行时字符串 | `Method` 编译期枚举 | 编译期错误检查 |

### 4.2 行为/健壮性改进

- **canary 校验**：`nmux` 高 64 位携带配置标志 canary（magic + 4 个开关位 + kf 低 12 位），
  两端配置不一致时握手显式报 `FlagsMismatch`，而不是静默断连；不匹配 magic 的对端仍向后兼容。
- **base94 解码失败不留部分输出**：解码中途出错即回滚，杜绝半解析状态。
- **帧长一致性校验**：内存解密路径严格校验 `len + 3 == packet.len()`，截断/拼接包直接拒绝。
- **错误类型化**：`Error` 枚举（`InvalidFrame` / `ChecksumMismatch` / `FlagsMismatch` 等），
  并区分 EOF 用于干净关闭检测。
- **零长度帧**：写路径拒绝空负载（与原版一致）。

### 4.3 架构差异

- **代理而非 VPN**：无虚拟网卡、无 PPP 层，核心只做"一条加密消息流"。
- **传输无关**：`Transmission<T>` 泛型化，流式与内存双路径共用同一套编解码状态机。
- **`split_with`**：拆成 `TransmissionTx` / `TransmissionRx` 两个半双工，支持经典双线程泵模型；
  每方向 nonce 与 base94 首帧状态独立，与未拆分对端线上兼容。
- **零分配热路径**：复用 scratch 缓冲区，避免每包分配。

### 4.4 保留的抗封锁设计（未改动）

- base94 可打印外壳（DPI 下无加密流量特征）；
- 随机化帧头 + 奇偶填充 + 长度混淆 + 首帧校验和（篡改/错误 kf 立即失败）；
- NOP 噪声前奏 + dummy session-id 包（抗主动探测）；
- 随机 padding 与随机包长（抗流量分析）；
- 每连接 ivv 派生独立密钥（抗会话关联）；
- 握手前强制全变换（safest 模式）。

## 5. 测试策略

- **golden vectors**（`tests/golden_vectors.rs`）：LCG/shuffle/delta/masked-XOR/base94/checksum/
  帧头/session-id 包与 C++ 参考实现逐字节交叉验证，防止移植漂移。
- **集成测试**（`tests/integration.rs`）：内存双工管道上跑完整握手 + 双向传输、mux 协商、
  canary 不匹配、kf 不匹配、错误密码、截断包、全密码组合互操作、split 半双工并发。