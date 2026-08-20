# nextppp-core 协议文档

> 本文档是 `crates/core` 的完整协议规范：从配置参数、密码学原语、帧格式、握手流程到数据面调度，
> 所有公式、字节布局与状态机均与 Rust 实现一一对应（代码索引格式为 `文件:行号`）。
>
> 协议算法源自 openppp2（C++ 原版规范见 `docs/openppp2-algo.md`）。本实现**不追求与原版字节级兼容**，
> 但完整保留了原版经过广泛验证的抗封锁设计；同时修正了原版若干密码学缺陷（见 §10）。
>
> 相关源码：
> - `crates/core/src/config.rs`（配置）
> - `crates/core/src/crypto/ssea.rs`（混淆原语）
> - `crates/core/src/crypto/cipher.rs`（会话密码）
> - `crates/core/src/frame/base94.rs`、`frame/binary.rs`、`frame/checksum.rs`（帧化）
> - `crates/core/src/handshake.rs`（握手）
> - `crates/core/src/transmission.rs`（数据面）
> - `crates/core/src/error.rs`（错误类型）

---

## 1. 概述与定位

`nextppp-core` 是协议核心库：**帧化、混淆、握手、会话密码**，全部与 I/O 传输解耦。
它不关心 TCP/UDP/网卡，只提供两种使用方式：

- **流式**：`Transmission<T: Read + Write>` 直接包住任意双工字节流（TCP 等），提供
  `handshake_client` / `handshake_server` / `read` / `write`。
- **内存**：`encrypt_into` / `decrypt` 不触碰传输层，把明文编成一个完整线上包（或反向），
  供 datagram / mux 风格的上层使用。

协议的核心设计目标：**在握手完成前（以及 `plaintext=true` 时）线上流量全部为可打印 ASCII**，
配合随机化帧头、噪声前奏、每连接独立密钥等机制，使流量在 DPI 面前不具备加密流量特征。

## 2. 全局常量（`lib.rs:44-54`）

| 常量 | 值 | 含义 |
|------|-----|------|
| `PPP_BUFFER_SIZE` | 65536 | 单帧明文上限（字节） |
| `BASE94_MAX_FRAME` | `2 * 65536 + 64` = 131136 | base94 帧编码后长度上限 |
| `MOD_MIN` | `64^3` = 262144 | 长度混淆模数下限 |
| `MOD_MAX` | `94^3` = 830584 | 长度混淆模数上限 |
| `BASE94_SYMBOL_COUNT` | 94 | base94 符号数（0x20..0x7E） |
| `BASE94_DECIMAL_MAX_LEN` | 10 | u64 的 base94 最大位数（94^10 > 2^64） |
| `SessionId` | `u128` | 128 位会话标识 |

## 3. 配置参数（`config.rs`）

`ObfuscationKey` 是两端共享的协议参数，除密码外的所有字段都参与 flag canary（§7.6），
因此两端配置不一致时握手会显式报 `FlagsMismatch`，而不是静默断连。

| 字段 | 默认值 | 含义 |
|------|--------|------|
| `kf` | 154543927 | 全局混淆密钥：驱动 base94/delta/masked 变换与长度模数 |
| `kl` | 10 | NOP 前奏轮数下限指数（轮数采样于 `2^kl ..= 2^kh`） |
| `kh` | 12 | NOP 前奏轮数上限指数 |
| `kx` | 128 | 握手包 padding 量（实际取 `kx % 256`） |
| `protocol` | `Aes128Cfb` | 帧头长度字段保护密码 |
| `protocol_key` | `"nextppp"` | 协议密码口令，**部署必须修改** |
| `transport` | `Aes256Cfb` | 负载保护密码 |
| `transport_key` | `"nextppp"` | 传输密码口令，**部署必须修改** |
| `masked` | true | 负载 masked-XOR 开关（数据面；握手前强制开启） |
| `plaintext` | true | 握手后是否保留 base94 可打印外壳；`false` 则切换紧凑 3 字节二进制帧头 |
| `delta_encode` | true | 负载 delta 编码开关 |
| `shuffle_data` | true | 负载 shuffle 开关 |

## 4. 密码学原语（`crypto/ssea.rs`）

全部原语是 openppp2 `ssea.cpp` 的忠实移植，保留参考实现的字节级语义
（含截断/回绕的 `Byte(int)` 转换），保证抗封锁行为与原版一致。

### 4.1 LCG PRNG（`ssea.rs:24-34`）

31 位输出的三步 LCG，每次调用推进种子 3 次：

```
lcg_next(seed):
    next = seed * 1103515245 + 12345            # mod 2^32
    result = (next / 65536) % 2048
    next = next * 1103515245 + 12345
    result = (result << 10) ^ ((next / 65536) % 1024)
    next = next * 1103515245 + 12345
    result = (result << 10) ^ ((next / 65536) % 1024)
    seed = next
    return result                               # 31 位
```

闭区间采样（`ssea.rs:38-41`）：`lcg_range(seed, min, max) = lcg_next(seed) % (max - min + 1) + min`。

> 注意：LCG 只用于**确定性可复现的变换**（长度模数、masked XOR 密钥流），
> 不用于生成随机数——所有随机性来自 CSPRNG（`StdRng::from_os_rng()`）。

### 4.2 shuffle / unshuffle（`ssea.rs:49-72`）

密钥驱动的确定性置换：

```
shuffle(data, key):
    for i in 0..len(data):
        j = (i ^ key) % len(data)
        swap(data[i], data[j])

unshuffle(data, key):   # 逆操作：反向执行同一交换序列
    for i in (0..len(data)).rev():
        j = (i ^ key) % len(data)
        swap(data[i], data[j])
```

- 不是密码学置换，但足以对抗朴素 DPI 模式匹配，代价可忽略。
- `len <= 2` 时退化为恒等置换（与原版一致，属设计行为）。

### 4.3 delta 编解码（`ssea.rs:77-103`）

```
delta_encode(data, kf):
    out[0] = data[0] - kf            # mod 256
    out[i] = data[i] - data[i-1]     # i >= 1，mod 256

delta_decode(data, kf):              # 逆操作
    out[0] = data[0] + kf
    out[i] = out[i-1] + data[i]
```

### 4.4 masked XOR（`ssea.rs:110-128`）

按 4 字节字 → 2 字节半字 → 1 字节顺序处理，**每个块处理完后**用 LCG 推进密钥：

```
masked_xor_random_next(data, kf):
    kf = lcg_next(kf)                        # 先推进一次
    for each 4-byte word:  word ^= kf (小端);  kf = lcg_next(kf)
    if remainder >= 2:      halfword ^= kf (小端 u16);  kf = lcg_next(kf)
    if remainder odd:       last byte ^= kf (低字节)
```

对固定初始密钥自逆（加密与解密是同一函数）。

### 4.5 base94 字节编解码（`crates/base94/src/lib.rs`，SIMD 实现 `crates/base94/src/simd.rs`）

**编码**：每个输入字节 `b` 映射为 1~2 个可打印字符（0x20..0x7E）：

```
v = (b - kf) mod 256
if v >= 93:                       # 双字符转义
    c1 = 0x20 + (v / 93 - 1 + 93)       # v/93 ∈ {1,2} → c1 ∈ {0x7D, 0x7E}
    c2 = 0x20 + (v % 93)                # c2 ∈ [0x20, 0x7C]
else:
    c1 = 0x20 + v                       # c1 ∈ [0x20, 0x7C]
```

输出长度最坏为输入的 2 倍（`base94_encoded_len` 可预计算）。

**解码**（`crates/base94/src/lib.rs` 的 `decode_into`）：

```
对每个字符 c:
    校验 c >= 0x20，否则失败
    b = c - 0x20
    if b < 93:  out = b + kf; 继续
    # 转义序列
    校验 b <= 94（即 c <= 0x7E），否则失败
    校验存在下一字符 c2 且 c2 >= 0x20，否则失败
    b2 = c2 - 0x20；校验 b2 <= 93，否则失败
    v = (b - 93 + 1) * 93 + b2
    校验 v <= 0xFF（仅 b == 94 可能溢出：b2 > 0xFF - 2*93 时失败）
    out = v + kf
```

**失败时不留部分输出**：解码中途出错即回滚到起始位置（`out.truncate(start)`），杜绝半解析状态。

### 4.6 base94 整数编解码（`crates/base94/src/lib.rs`）

u64 与 base94 数字串（字符 0x20..0x7D）互转，**最少位数、无前导零**：

```
base94_decimal_encode(v):   # 反复除 94 取余，倒序
    digits = []
    do: digits.push(v % 94 + 0x20); v /= 94; while v > 0
    return reverse(digits)

base94_decimal_decode(s):   # 校验每个字符 c >= 0x20 且 c - 0x20 < 94
    n = 0
    for each char c: n = n * 94 + (c - 0x20)
    return n
```

解码接受前导 0x20 填充（帧头固定 3 位读取依赖此特性）。

### 4.7 Internet checksum（`frame/checksum.rs`）

标准 RFC 1071 反码和（匹配 lwIP `inet_chksum`）：按 16 位大端字累加、折叠进位、取反；
奇数尾字节作为高字节参与累加。用于 base94 首帧扩展头的篡改检测。

## 5. 会话密码（`crypto/cipher.rs`）

### 5.1 Method 枚举（`cipher.rs:26-37`）

编译期枚举取代原版的运行时密码名字符串：

| Method | 密钥长 | IV/nonce 长 | 说明 |
|--------|--------|-------------|------|
| `Aes128Cfb` | 16 | 16 | 原版默认协议密码 |
| `Aes256Cfb` | 32 | 16 | 原版默认传输密码 |
| `Aes128Ctr` | 16 | 16 | 新增 |
| `Aes256Ctr` | 32 | 16 | 新增 |
| `ChaCha20` | 32 | 12 | 新增，无 AES-NI 的机器上更快 |

`from_name` / `name` 提供与 openppp2 风格密码名的互转（配置层使用）。

### 5.2 密钥派生（`cipher.rs:119-151`）

```
ikm = password_bytes || ('+' if ivv > 0) || base32(ivv)
salt = "nextppp/" + role.name() + "/" + method.name()
okm = HKDF-SHA256(ikm, salt, info = "nextppp-session-key", L = 48)
key     = okm[0..32]
base_iv = okm[32..48]
```

- `base32` 为小写字母表 `0123456789abcdefghijklmnopqrstuv`（`cipher.rs:246-259`），
  最少位数（`ivv=0` → `"0"`），保留原版 `"+" + base32(ivv)` 的 ivv 字符串格式。
- `SessionCipher::new(method, role, password)` 等价于 `derive(method, role, password, None)`，
  用于握手前阶段（与原版在 ITransmission 构造时初始化密码一致）。
- 每连接由客户端随机 `ivv` 派生独立工作密钥，防多连接指纹关联。

#### 5.2.1 `protocol_key` 与 `transport_key` 能否共用同一个口令？

**可以，且不损失安全性**。分析如下：

- 两个 cipher 的派生 salt 不同（`nextppp/protocol/{method}` vs
  `nextppp/transport/{method}`），HKDF 的域分离保证即使口令、method 全部相同，
  protocol（帧头长度字段，每包 2 字节）与 transport（负载）也永远派生不同的
  key/IV，即不同的 keystream。
- 若**没有** role 域分离：当用户把两个 method 配成相同且口令相同时，两层会派生
  出完全相同的 key+base_iv，且两层 nonce 计数器都从 0 起——同包内 2 字节长度字段
  与负载前缀使用同一 keystream 段（two-time pad），攻击者可用已知明文的负载恢复
  keystream 进而解密长度字段。虽然长度字段本身敏感度低（线上帧长大致可见），
  但这违反密钥分离原则，因此实现中加入了 role 域分离，从根本上排除该情况。
- 域分离后，"两层用同一个口令"与"两个独立口令"的安全边界完全一致：
  单个口令的熵足够时（长随机口令），两层密钥互不影响；
  口令过弱时（弱口令被猜出），无论一层还是两层配独立弱口令，攻击者同样能各自
  派生——分层口令并不会显著提高抗口令猜测强度（HKDF 单一出口）。

结论：应用层配置提供统一的 `password` 选项（`protocol_key`/`transport_key`
留空时回退到它）是安全的默认。

> **口令熵即安全边界**：HKDF 无口令拉伸（单轮 SHA-256），salt/info 是公开常量。
> 被动观察者可以离线枚举弱口令，并用首帧校验和作为验证 oracle。请使用长随机口令。

### 5.3 nonce 管理（`cipher.rs:222-241`）

TLS-1.3 风格：`nonce = base_iv XOR be64(seq)`，每方向单调递增的 64 位计数器：

```
nonce = base_iv
xor_width = 8 (AES) / 4 (ChaCha20)
nonce[iv_len - xor_width ..] ^= be64(seq) 的低 xor_width 字节
seq += 1
```

- **修复原版 two-time pad 漏洞**：原版每包用相同 key/IV 重新初始化 EVP 上下文，
  所有包复用同一 keystream（`C1^C2 = P1^P2`）；本实现每包 nonce 唯一。
- 一个 `SessionCipher` 实例只能服务一条消息流；每方向各建一个实例
  （tx 用加密实例，rx 用 `for_decryption()` 实例；CFB 加解密不对称，CTR/ChaCha20 对称）。
- 64 位计数器在单连接内实际不可能回绕（2^64 包 × 64KiB 远超任何会话规模）；
  ChaCha20 的 32 位 XOR 宽度同样安全（重复一个 nonce 需单方向 2^32 包 ≈ 256 TiB）。

> **部署提示（吞吐）**：CFB 的加密方向是串行反馈链（≈3 c/B），解密已批量化但
> server 的下行（大流量方向）走的是加密。高吞吐场景建议把 `transport` 配置为
> `aes-256-ctr` 或 `chacha20-ietf`（两者全并行，wire 语义与 CFB 互不兼容，
> 两端需一致）。

## 6. 帧格式

### 6.1 帧类型总览

由 `handshaked` 标志与 `key.plaintext` 共同决定（`transmission.rs:163-168, 249-267`）：

| 阶段 | 帧类型 | 帧头 | 判定条件 |
|------|--------|------|----------|
| 握手完成前 | base94 帧 | 4 字节（首帧 7 字节） | `!handshaked` |
| 握手完成后 | base94 帧 | 4 字节（首帧 7 字节） | `handshaked && plaintext` |
| 握手完成后 | 二进制帧 | 3 字节 | `handshaked && !plaintext` |

两种帧是**嵌套**关系：二进制帧是内层加密包，base94 帧是外层可打印外壳。

### 6.2 base94 帧（`frame/base94.rs`）

```
首帧:   [k][f][d1][d2][d3][c1][c2][c3]   7 字节扩展头
后续帧: [k][f][d1][d2][d3]               4 字节简单头
        [ base94 编码的二进制包 ... ]
```

#### 6.2.1 帧头构造（`base94.rs:95-142`）

```
MOD    = lcg_range(kf, 262144, 830584)        # 构造时从 kf 派生一次
KF_MOD = abs((kf as i32) % (MOD as i32))

N = (encoded_len + KF_MOD) % MOD              # encoded_len 为 base94 编码后长度
d = base94_decimal(N)                         # 最少位数，dl ∈ {1,2,3}
校验 1 <= dl < 4，否则失败

h[7] = { 0x20, 0x20, 0x20, 0x20, 0, 0, 0 }
h[4-dl .. 4] = d                              # 长度数字右对齐放在 h[1..4] 区域

k = h[0] = random(0x20..=0x7E)
if h[1] == 0x20:                              # dl < 3，h[1] 未被长度数字覆盖
    if k 为奇数: k += 1                       # 强制 k 偶数（0x7E 为偶数，不会溢出）
    h[1] = random(0x20..=0x7E)                # 随机 filler
else:                                         # dl == 3，h[1] 是真实长度数字
    if k 为偶数: k += 1；若 k > 0x7E 则 k = 0x21   # 强制 k 奇数
h[0] = k
swap(h[2], h[3])                              # 长度数字字节交换
```

> 不变式：`h[1] == 0x20` 当且仅当 `dl < 3`——因为 base94 整数编码无前导零，
> 3 位数字的首位不可能是 0x20。

#### 6.2.2 奇偶性机制（关键）

`k` 的奇偶性编码了 `h[1]` 的语义：

- `dl < 3`（长度数字未占满 h[1..4]）：`k` 必为**偶数**，`h[1]` 是随机 filler，解码端忽略；
- `dl == 3`（长度数字占满 h[1..4]）：`k` 必为**奇数**，`h[1]` 是长度数字的一部分，解码端保留。

#### 6.2.3 首帧扩展头（`base94.rs:127-138`）

每个方向的**发送首帧**额外携带 3 字节校验和（`tx_first` 标志，收发独立）：

```
chk = inet_chksum(h[0..4]) ^ encoded_len      # 注意：校验和覆盖交换后的帧头
cn  = (chk + KF_MOD) % MOD
d   = base94_decimal(cn)，校验位数恰为 3
h[4..7] = d
shuffle(h[4..7], kf)                          # 校验和数字 shuffle
tx_first = false                              # 此后发送方切简单头
```

任何流损坏或 kf 不匹配都会使校验失败，立即报 `ChecksumMismatch`。

#### 6.2.4 帧头解析（`base94.rs:146-187`）

**恢复规范形** `restore_header`：

```
if k 为偶数: h[1] = 0x20                     # 丢弃 filler
h[0] = 0x20                                   # 恢复种子字节
swap(h[2], h[3])                              # 撤销字节交换
```

**长度解码** `decode_length`：

```
N = base94_decimal(h[1..4])                   # 固定读 3 字节（前导 0x20 视为 0）
length = (N - KF_MOD + MOD) % MOD
```

**首帧扩展头校验** `decode_header_extended`（`base94.rs:164-177`）：

```
读 7 字节
chk = inet_chksum(h[0..4])
restore_header(h[0..4])
payload_length = decode_length(h[1..4])；校验 >= 1
unshuffle(h[4..7], kf)
n = decode_length(h[4..7])
校验 n == chk ^ payload_length，否则报 ChecksumMismatch
```

**后续帧** `decode_header_simple`：读 4 字节 → `restore_header` → 长度解码。

#### 6.2.5 完整帧组装（`base94.rs:76-91, 200-255`）

**发送** `encode_frame`：

```
encoded_len = base94_encoded_len(binary, kf)
校验 encoded_len <= BASE94_MAX_FRAME (131136)
packet = header || base94_encode(binary, kf)
```

**流式接收** `read_frame`：按 `rx_first` 读 7 或 4 字节头 → 解码长度 →
校验 `1 <= len <= 131136` → 读 `len` 字节 → base94 解码。
`rx_first` 标志**仅在整帧校验通过后**才翻转（失败不推进状态）。

**内存接收** `decode_packet`（`base94.rs:228-255`）：额外校验
`len + header_len == packet.len()`，截断/拼接包直接拒绝。

### 6.3 二进制帧（`frame/binary.rs`）

```
packet = header[3] || payload
```

#### 6.3.1 帧头加密 `header_encrypt`（`binary.rs:74-99`）

```
adjusted = payload_len - 1                    # 65536 → 65535，避免全零长度字段
array[3] = { seed, adjusted >> 8, adjusted & 0xFF }
seed = random(1..=0xFF)                       # 每包随机
header_kf = kf ^ seed

if protocol 密码存在:
    array[1..3] = protocol.encrypt(array[1..3])   # 2 字节，消耗一个 nonce

array[1] ^= header_kf; array[2] ^= header_kf      # 逐字节 XOR（低字节）
shuffle(array[1..3], header_kf)
array = delta_encode(array, 3, kf)
```

#### 6.3.2 帧头解密 `header_decrypt`（`binary.rs:102-118`）

```
array = delta_decode(header, 3, kf)
header_kf = kf ^ array[0]
unshuffle(array[1..3], header_kf)
array[1] ^= header_kf; array[2] ^= header_kf
if protocol 密码存在:
    array[1..3] = protocol.decrypt(array[1..3])
len = (array[1] << 8 | array[2]) + 1
```

#### 6.3.3 负载变换（`binary.rs:120-145`）

```
payload_obfuscate(data, flags, header_kf, kf):     # 顺序固定
    if masked:  masked_xor_random_next(data, header_kf)
    if shuffle: shuffle(data, header_kf)
    if delta:   delta_encode(data, kf)              # 注意 delta 用配置 kf，其余用 header_kf

payload_deobfuscate(data, flags, header_kf, kf):    # 逆序逆操作
    if delta:   delta_decode(data, kf)
    if shuffle: unshuffle(data, header_kf)
    if masked:  masked_xor_random_next(data, header_kf)   # XOR 自逆
```

**safest 模式**：握手前（`!handshaked`）强制全部三个变换开启，忽略配置开关
（`PayloadFlags::SAFEST`，`binary.rs:54-58`；`transmission.rs:207-217`）。

### 6.4 帧大小限制

| 检查点 | 上限 | 位置 |
|--------|------|------|
| base94 编码后长度 | 131136 | `base94.rs:83` |
| 二进制帧头解码长度 | 1..=65536 | `transmission.rs:188-190` |
| 内存路径长度一致性 | `len + 3 == packet.len()` | `transmission.rs:192-194` |
| 写路径空负载 | 拒绝（`Error::ZeroLength`） | `transmission.rs:136-138` |

## 7. 握手协议（`handshake.rs` + `transmission.rs:274-373`）

### 7.1 时序总览

```
client: nop* ->          <- sid (server session id)
client:      ivv ->      <- nmux (mux parity + flag canary in high 64 bits)
both:   rekey ciphers from ivv, switch to data-plane framing
```

握手期间所有包都走完整加密管线（safest 变换 + base94 外壳），线上保持可打印 ASCII。

### 7.2 NOP 前奏（`handshake.rs:57-71`）

```
kl = 1 << key.kl        # 默认 1024
kh = 1 << key.kh        # 默认 4096
if kl > kh: swap(kl, kh)
rounds = (kl == kh) ? kl : random(kl..=kh)     # 闭区间
rounds = ceil(rounds / 1400)                   # 默认得 1..3
发送 rounds 个 dummy session-id 包
```

作用：连接建立初期产生随机数量的纯噪声包，抗主动探测与流量指纹。

### 7.3 session-id 包（`handshake.rs:75-180`）

```
packet = kfs[4] || body

kfs[0] = real ? random(0x00..=0x7F) : random(0x80..=0xFF)   # MSB 标记 dummy
kfs[1..3] = random(0x01..=0xFF) × 3

body = decimal(id)                            # 真实包：会话标识；dummy：随机 128 位
body += random(0x20..=0x2F)                   # 分隔符（非数字，终止十进制解析）

# 抗流量分析 padding
max = key.kx % 0x100                          # 默认 128
if max > 0:
    body += max 个 random(0x20..=0x7E)
    body += '/'
    effective_max = max(max, body.len() + 4)
    body += random(1..=effective_max * 4) 个 random(0x20..=0x7E)

# 4 轮 XOR 加密
kf = key.kf
for i in 0..4:
    kf ^= kfs[i]
    body[j] ^= kf (低字节) 对所有 j
```

**数学性质**：`kf` 出现在全部 4 轮密钥中，完整链后其贡献抵消——
净效果等价于每字节异或 `kfs[1] ^ kfs[3]`（`handshake.rs:252-266` 有测试证明）。
因此该层是纯混淆（对抗朴素指纹识别），不提供保密性；会话值本身也非机密。

**解析** `unpack_session_id`（`handshake.rs:142-180`）：

```
校验 packet.len() >= 4
if packet[0] & 0x80: 返回 Dummy（接收方跳过）
按相同 4 轮 XOR 解密 body
解析十进制前缀直到非数字分隔符；无数字 → InvalidSessionId
```

### 7.4 客户端握手 `handshake_client`（`transmission.rs:276-311`）

```
1. NOP 前奏（§7.2）
2. sid = 读 session-id 包（循环跳过 dummy）；sid == 0 → 失败
3. ivv = random u128；ivv == 0 → 失败（重新生成）
4. 发送 ivv 包
5. nmux = 读 session-id 包；nmux == 0 → 失败
6. mux = nmux & 1 == 1                        # 最低位协商多路复用
7. canary 校验（§7.6）
8. rekey(ivv)（§7.7）；handshaked = true
返回 (sid, mux)
```

### 7.5 服务端握手 `handshake_server`（`transmission.rs:316-347`）

```
1. NOP 前奏（§7.2）
2. 发送 session_id 包（上层提供的非零会话标识）
3. nmux = (flag_canary(key) << 64) | random u64
   若 mux 请求: 使 nmux 为奇数（while nmux & 1 == 0: nmux += 1）
   否则:       使 nmux 为偶数（while nmux & 1 != 0: nmux += 1）
4. 发送 nmux 包
5. ivv = 读 session-id 包（循环跳过 dummy）；ivv == 0 → 失败
6. rekey(ivv)；handshaked = true
```

### 7.6 混淆标志 canary（`handshake.rs:45-52`）

```
magic = 0xC0DEC0DEC0DE                        # 48 位
flags = masked | (plaintext << 1) | (delta_encode << 2) | (shuffle_data << 3)
canary = magic | (flags << 48) | ((kf & 0xFFF) << 52)
```

客户端校验（`transmission.rs:299-305`）：

```
nmux_high = nmux >> 64
if nmux_high & 0x0000FFFFFFFFFFFF == 0xC0DEC0DEC0DE:   # 2^-48 碰撞概率
    要求 nmux_high == 本地 canary，否则报 FlagsMismatch
else:
    视为旧版对端，静默跳过（向后兼容）
```

作用：两端 `masked`/`plaintext`/`delta_encode`/`shuffle_data`/`kf` 不一致时
握手显式失败，而不是静默断连后数据全乱。

### 7.7 会话密钥重建 `rekey`（`transmission.rs:220-231`）

```
ivv_str = "+" + base32(ivv)                   # ivv > 0 恒成立（零值被拒绝）
protocol_tx/rx  = SessionCipher::derive(protocol, Protocol, protocol_key, Some(ivv))
transport_tx/rx = SessionCipher::derive(transport, Transport, transport_key, Some(ivv))
```

四个密码实例全部重建，nonce 计数器归零。此后数据面使用新密钥。

## 8. 数据面（`transmission.rs`）

### 8.1 发送管线 `write` / `encrypt_into`（`transmission.rs:135-169, 237-245`）

```
write(plaintext):
    encrypt_into(out, plaintext) → io.write_all(out)

encrypt_into(out, plaintext):
    校验 1 <= len <= 65536，否则 ZeroLength / FrameTooLarge
    flags = handshaked ? 配置开关 : SAFEST
    (header, header_kf) = header_encrypt(rng, kf, protocol_tx, len)   # 协议密码消耗 nonce
    bin = header || plaintext
    transport_tx.apply(bin[3..])                                      # 传输密码消耗 nonce
    payload_obfuscate(bin[3..], flags, header_kf, kf)
    if !handshaked || plaintext:  b94.encode_frame(rng, out, bin)     # base94 外壳
    else:                        out.extend(bin)                      # 裸二进制
```

### 8.2 接收管线 `read` / `decrypt`（`transmission.rs:173-204, 248-268`）

```
read():
    if !handshaked || plaintext:
        binary = b94.read_frame(io)            # 流式 base94 帧
    else:
        读 3 字节头 → header_decrypt → 校验 1 <= len <= 65536
        读 len 字节 body
    decrypt_packet(binary)

decrypt_packet(binary):
    校验 binary.len() > 3
    (len, header_kf) = header_decrypt(kf, protocol_rx, header)        # 协议密码消耗 nonce
    校验 1 <= len <= 65536
    校验 len + 3 == binary.len()               # 截断/拼接防护（内存路径）
    payload_deobfuscate(body, flags, header_kf, kf)
    transport_rx.apply(body)                                          # 传输密码消耗 nonce
```

> 流式二进制路径不做 `len + 3` 一致性校验——长度来自流本身，天然一致。

### 8.3 内存路径

`encrypt_into` / `decrypt` 不触碰传输层，适用于 datagram / mux 风格的上层
（如 vmux 复用连接时把每条消息编成独立包）。与流式路径共享同一套编解码状态机，
两种路径线上互操作（`tests/integration.rs:258-282` 验证）。

### 8.4 半双工拆分 `split_with`（`transmission.rs:560-606`）

```
split_with(rx_io) -> (TransmissionTx, TransmissionRx)
```

- `TransmissionTx` 持有原 `io` 作为**写**侧 + tx 方向密码/b94 首帧状态；
- `TransmissionRx` 使用调用者传入的 `rx_io` 作为**读**侧（须与写侧别名同一连接，
  如 `TcpStream::try_clone`，且必须在 split 之前克隆）。
- 每方向 nonce 与 base94 首帧状态本就独立跟踪，拆分后与未拆分对端**线上兼容**。
- 支持经典双线程泵模型：写线程只写、读线程只读。

## 9. 错误处理（`error.rs`）

| 错误 | 触发条件 |
|------|----------|
| `Io` | 底层传输 I/O 失败（连接重置、EOF、超时） |
| `InvalidFrame` | 帧头/帧体结构校验失败、长度不一致 |
| `InvalidBase94` | base94 字符越界、转义截断/溢出 |
| `ChecksumMismatch` | 首帧扩展头校验和不匹配（流损坏/篡改/kf 错误） |
| `InvalidSessionId` | session-id 包解析失败 |
| `HandshakeFailed` | 握手序列失败（阶段描述在静态字符串中） |
| `FlagsMismatch` | canary 不匹配（两端混淆配置不一致） |
| `FrameTooLarge` | 解码长度超上限 |
| `ZeroLength` | 写路径拒绝空负载 |

`Error::is_eof()` 用于区分干净关闭（`UnexpectedEof`）与其他 I/O 错误，方便读循环退出。

## 10. 与原版 openppp2 的差异

### 10.1 密码学修正（安全）

| 原版 | 新版 | 原因 |
|------|------|------|
| `EVP_BytesToKey(MD5, 1 round)` + MD5 IV 搅动 + 自定义 RC4 再搅 IV | HKDF-SHA256（salt 含方法名） | MD5 系 KDF 过弱，RC4 搅动只算混淆不算安全 |
| 每包用**相同 key/IV** 重新初始化 EVP 上下文 → 全部包复用同一 keystream（two-time pad） | TLS-1.3 风格 `nonce = base_iv XOR be64(seq)`，每方向单调 64 位计数器 | 修复 keystream 重用漏洞 |
| .NET 风格 56 槽减法生成器 | `StdRng::from_os_rng()`（CSPRNG） | 协议不依赖随机序列，只依赖分布，可安全替换 |
| 自定义 RC4-255 密码族（`rc4-md5` 等） | 删除；新增 AES-CTR / ChaCha20 | RC4 已破，新 KDF 不再需要它 |
| 密码名运行时字符串 | `Method` 编译期枚举 | 编译期错误检查 |

### 10.2 行为/健壮性改进

- **canary 校验**：`nmux` 高 64 位携带配置标志 canary（magic + 4 个开关位 + kf 低 12 位），
  两端配置不一致时握手显式报 `FlagsMismatch`，而不是静默断连；不匹配 magic 的对端仍向后兼容。
- **base94 解码失败不留部分输出**：解码中途出错即回滚，杜绝半解析状态。
- **帧长一致性校验**：内存解密路径严格校验 `len + 3 == packet.len()`，截断/拼接包直接拒绝。
- **错误类型化**：`Error` 枚举（`InvalidFrame` / `ChecksumMismatch` / `FlagsMismatch` 等），
  并区分 EOF 用于干净关闭检测。
- **零长度帧**：写路径拒绝空负载（与原版一致）。

### 10.3 架构差异

- **代理而非 VPN**：无虚拟网卡、无 PPP 层，核心只做"一条加密消息流"。
- **传输无关**：`Transmission<T>` 泛型化，流式与内存双路径共用同一套编解码状态机。
- **`split_with`**：拆成 `TransmissionTx` / `TransmissionRx` 两个半双工，支持经典双线程泵模型；
  每方向 nonce 与 base94 首帧状态独立，与未拆分对端线上兼容。
- **零分配热路径**：复用 scratch 缓冲区，避免每包分配（`read_buf`/`read_frame_into` 借用式 API）。
- **SIMD base94**：编解码 16 字节块走 SIMD 快路径（leader/follower 交替求解 + pshufb LUT 压缩），
  非法输入与尾部回退标量参考路径，错误语义逐位一致（fuzz + golden vectors 锚定）；x86_64 约 3×/2.6×。
- **可观测性**：`hotpath` feature（默认关闭、Windows 构建零开销）对关键路径打点输出计时报告。

### 10.4 保留的抗封锁设计（未改动）

- base94 可打印外壳（DPI 下无加密流量特征）；
- 随机化帧头 + 奇偶填充 + 长度混淆 + 首帧校验和（篡改/错误 kf 立即失败）；
- NOP 噪声前奏 + dummy session-id 包（抗主动探测）；
- 随机 padding 与随机包长（抗流量分析）；
- 每连接 ivv 派生独立密钥（抗会话关联）；
- 握手前强制全变换（safest 模式）。

## 11. 抗封锁设计原理（对应关系）

| 对抗目标 | 机制 | 位置 |
|----------|------|------|
| DPI 识别加密流量特征 | 握手前全部流量为可打印 ASCII（base94） | §6.2 |
| 固定特征指纹 | 帧头随机种子、随机 filler、长度混淆、字节交换、shuffle | §6.2.1、§6.3.1 |
| 主动探测（连接即发特征包） | NOP 噪声前奏 + dummy 包 | §7.2、§7.3 |
| 流量分析（包长/时序） | 随机 padding、随机轮数、随机包长 | §7.3、§7.2 |
| 会话关联（多连接指纹相同） | 每连接 ivv 派生独立工作密钥 | §7.7 |
| 篡改/重放 | 首帧校验和（`inet_chksum ^ length`）、帧长一致性校验 | §6.2.3、§8.2 |
| 配置不一致导致静默断连 | canary 显式报错 | §7.6 |

## 12. 使用示例

```rust
use nextppp_core::{ObfuscationKey, Transmission};

// 客户端
let io = std::net::TcpStream::connect("1.2.3.4:1234")?;
let mut tx = Transmission::new(io, ObfuscationKey::default());
let (session, mux) = tx.handshake_client()?;
tx.write(b"hello")?;
let reply = tx.read()?;

// 服务端（每连接一个线程/任务）
let mut server = Transmission::new(stream, key);
server.handshake_server(session_id, mux_requested)?;
loop {
    match server.read() {
        Ok(msg) => server.write(&handle(msg))?,
        Err(e) if e.is_eof() => break,   // 干净关闭
        Err(e) => return Err(e.into()),
    }
}

// 双线程泵模型
let rx_io = tx.io().try_clone()?;
let (mut tx_half, mut rx_half) = tx.split_with(rx_io);
// 写线程: tx_half.write(...)  读线程: rx_half.read(...)
```

## 13. 测试策略

- **golden vectors**（`tests/golden_vectors.rs`）：LCG/shuffle/delta/masked-XOR/base94/checksum/
  帧头/session-id 包与 C++ 参考实现逐字节交叉验证（向量由 `tools/vectors.cpp` 生成），
  防止移植漂移。
- **集成测试**（`tests/integration.rs`）：内存双工管道上跑完整握手 + 双向传输、mux 协商、
  canary 不匹配、kf 不匹配、错误密码、截断包、全密码组合互操作、split 半双工并发、
  握手前流量可打印性、零长度拒绝、EOF 检测。