# OPENPPP2 抗封锁传输算法完整复现规范

> 本文档从源码逐行提取 OPENPPP2 的传输层抗封锁算法，目标是：读者在**不参考本项目代码**的前提下，仅凭本文即可在自己的代码中实现一个**字节级兼容**的对端。
> 所有公式、字节布局、顺序均与源码一致。代码索引格式为 `文件:行号`。
>
> 核心源码：
> - `ppp/transmissions/ITransmission.cpp`（帧化、握手、数据面）
> - `ppp/cryptography/ssea.cpp`（混淆原语）
> - `ppp/cryptography/rc4.cpp`、`ppp/cryptography/EVP.cpp`（会话密码）
> - `ppp/configurations/AppConfiguration.cpp`（默认参数）

---

## 1. 全局常量

| 常量 | 值 | 来源 |
|------|-----|------|
| `PPP_BUFFER_SIZE` | 65536（单帧明文上限） | `ppp/stdafx.h:376` |
| `EVP_HEADER_TSS` | 2（加密长度字段字节数） | `ITransmission.cpp:45` |
| `EVP_HEADER_MSS` | 3（二进制帧头总长） | `ITransmission.cpp:46` |
| `EVP_HEADER_XSS` | 4（base94 简单帧头长） | `ITransmission.cpp:47` |
| `EVP_BASE94_MAX_FRAME` | `2 * PPP_BUFFER_SIZE + 64` = 131136（base94 帧长度上限） | `ITransmission.cpp:59` |
| `BASE94_SYMBOL_COUNT` | 94 | `ssea.cpp:16` |
| `BASE94_INPUT_BLOCK_SIZE` | 9（仅注释参考，未用于字节编解码） | `ssea.cpp:17` |
| `BASE94_OUTPUT_BLOCK_SIZE` | 11（仅用于整数编解码的缓冲上限） | `ssea.cpp:18` |
| `RC4_MAXBIT` | 255（自定义 RC4 S-box 长度，非标准 256） | `rc4.cpp:72` |
| `EVP_HEADER_MSS_MIN_MOD` | `64*64*64` = 262144 | `AppConfiguration.cpp:242` |
| `EVP_HEADER_MSS_MAX_MOD` | `94*94*94` = 830584 | `AppConfiguration.cpp:243` |

### 1.1 默认配置参数（`AppConfiguration.cpp:320-333`）

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `key.kf` | 154543927 | 全局混淆密钥（int32） |
| `key.kh` | 12 | NOP 轮数上限指数（`1 << kh`） |
| `key.kl` | 10 | NOP 轮数下限指数（`1 << kl`） |
| `key.kx` | 128 | 握手包 padding 量（`kx % 0x100`） |
| `key.sb` | 0 | shuffle 块大小（数据面未直接使用） |
| `key.protocol` | `"aes-128-cfb"` | 协议层密码算法 |
| `key.protocol_key` | `BOOST_BEAST_VERSION_STRING` | 协议层口令 |
| `key.transport` | `"aes-256-cfb"` | 传输层密码算法 |
| `key.transport_key` | `BOOST_BEAST_VERSION_STRING` | 传输层口令 |
| `key.masked` | true | 负载 masked XOR 开关 |
| `key.plaintext` | true | 强制 base94 明文模式开关 |
| `key.delta_encode` | true | delta 编码开关 |
| `key.shuffle_data` | true | shuffle 开关 |

> 注意：`plaintext=true` 时**握手完成后仍走 base94 帧**（见 §6.1 分支条件）；`plaintext=false` 时握手后走二进制帧。
> 默认配置下 `BOOST_BEAST_VERSION_STRING` 形如 `"boost/1.8x.x"`，实际部署必须修改。

---

## 2. 基础原语（全部可独立复现）

### 2.1 PRNG：`ssea::random_next`（`ssea.cpp:515-537`）

三步 LCG，每次输出 31 位随机数并推进种子：

```
random_next(seed):
    next = *seed
    next = next * 1103515245 + 12345
    result = (next / 65536) % 2048
    next = next * 1103515245 + 12345
    result = (result << 10) ^ ((next / 65536) % 1024)
    next = next * 1103515245 + 12345
    result = (result << 10) ^ ((next / 65536) % 1024)
    *seed = next
    return result
```

区间版（`ssea.cpp:556-560`）：`random_next(seed, min, max) = random_next(seed) % (max - min + 1) + min`。

**`lcgmod`**（`ssea.h:161`）：`lcgmod(kf, min, max) = random_next((uint32*)&kf, min, max)`——把 kf 当作种子原地推进。

### 2.2 全局随机源 `RandomNext`（`stdafx.cpp:255-264`）

`RandomNext()` = 全局 `Random` 对象（.NET 风格 56 槽减法生成器，`Random.cpp:58-123`）的 `Next(0, INT_MAX)`；`RandomNext(min, max)` 为闭区间 `[min, max]`。**复现时可用任意加密安全随机源替代**（协议不依赖其序列，只依赖其分布）。

### 2.3 `shuffle_data` / `unshuffle_data`（`ssea.cpp:40-82`）

```
shuffle_data(data, size, key):
    for i in 0..size-1:
        j = (i ^ key) % size
        swap(data[i], data[j])

unshuffle_data(data, size, key):   # 逆操作：反向执行同一交换序列
    for i in size-1..0:
        j = (i ^ key) % size
        swap(data[i], data[j])
```

### 2.4 `delta_encode` / `delta_decode`（`ssea.cpp:107-193`）

```
delta_encode(data, size, kf):
    out[0] = data[0] - kf
    out[i] = data[i] - data[i-1]      # i >= 1，字节减法（mod 256）

delta_decode(data, size, kf):
    out[0] = data[0] + kf
    out[i] = out[i-1] + data[i]       # i >= 1
```

### 2.5 `masked_xor_random_next`（`ssea.cpp:582-641`）

按 4 字节字 → 2 字节 → 1 字节顺序处理，**每个块处理完后** `kf = random_next(&kf)`（即 §2.1 的 LCG 推进）：

```
masked_xor_random_next(min, max, kf):
    length = max - min
    kf = random_next(&kf)                    # 先推进一次
    for each 4-byte word:  word ^= kf;  kf = random_next(&kf)
    if remainder >= 2:      halfword ^= kf;  kf = random_next(&kf)
    if remainder odd:       byte ^= kf
```

`masked_xor`（`ssea.cpp:661-664`）为同模板 `kf_random_next=false` 版本（不推进），数据面未使用。

### 2.6 字节级 base94 编解码（`ssea.cpp:220-393`）

**编码** `base94_encode(data, datalen, kf)`：对每个输入字节 `b`：

```
v = (b - kf) mod 256
if v >= 93:                       # 双字符转义
    c1 = 0x20 + ((v / 93 - 1) + 93)     # v/93 ∈ {1,2} → c1 ∈ {0x7D, 0x7E}
    c2 = 0x20 + (v % 93)                # c2 ∈ [0x20, 0x7C]
else:
    c1 = 0x20 + v                       # c1 ∈ [0x20, 0x7C]
```

输出长度：单字符 1 字节，双字符 2 字节，最坏 2×输入。

**解码** `base94_decode(data, datalen, kf)`：

```
对每个字符 c:
    b = c - 0x20
    校验: c >= 0x20；b <= 94（即 c <= 0x7E）；否则失败
    if b >= 93:                       # 转义，必须还有下一个字符
        取下一字符 c2: b2 = c2 - 0x20；校验 b2 <= 93
        v = ((b - 93) + 1) * 93 + b2
        校验 v <= 0xFF
        out = v + kf
    else:
        out = b + kf
```

解码校验规则（`ssea.cpp:318-362`）：字符 `< 0x20` 失败；`b > 94` 失败；转义字符 `b2 > 93` 失败；转义截断失败；`v > 0xFF` 失败。

### 2.7 整数 base94 编解码 `base94_decimal`（`ssea.cpp:409-499`）

```
base94_decimal(v):                    # uint64 → 字符串
    digits = []
    do: digits.push(v % 94 + 0x20); v /= 94; while v > 0
    return reverse(digits)            # 最少位数，无前导零

base94_decimal(data, datalen):        # 字符串 → uint64
    n = 0
    for each char c: 校验 c >= 0x20 且 c - 0x20 < 94；n = n * 94 + (c - 0x20)
    return n
```

### 2.8 Internet 校验和 `inet_chksum`（`checksum.h:220-222`）

标准 16 位反码和：`inet_chksum(data, len) = ~ip_standard_chksum(data, len)`。`ip_standard_chksum` 为经典 Internet checksum（`checksum.cpp:472` 起标量实现）：按 16 位大端字累加、折叠进位、取反。**任何标准实现均可，无需 SIMD 版本**。

---

## 3. 帧格式总览

传输层有两种帧，由 `handshaked_` 标志与 `key.plaintext` 决定：

| 阶段 | 帧类型 | 帧头 | 判定条件 |
|------|--------|------|----------|
| 握手完成前 | base94 帧 | 4 字节（首帧 7 字节） | `!handshaked_` |
| 握手完成后 | base94 帧 | 4 字节（首帧 7 字节） | `handshaked_ && key.plaintext` |
| 握手完成后 | 二进制帧 | 3 字节 | `handshaked_ && !key.plaintext` |

判定代码：`ITransmission.cpp:194-200`（读）、`ITransmission.cpp:135-138`（写）。

---

## 4. base94 帧（握手前 / plaintext 模式）

### 4.1 帧头构造 `base94_encode_length`（`ITransmission.cpp:325-382`）

**参数**：`length`（base94 编码后的负载长度）、`kf`（配置密钥）、`MOD`（见下）。

```
MOD    = Lcgmod(TRANSMISSION) = lcgmod(kf, 262144, 830584)   # AppConfiguration.cpp:1126
KF_MOD = abs(kf % MOD)

N = (length + KF_MOD) % MOD
d = base94_decimal(N)                    # 最少位数，dl ∈ {1,2,3}
校验: 1 <= dl < 4，否则失败

h[7] = { 0x20, 0x20, 0x20, 0x20, 0, 0, 0 }
memcpy(h + (4 - dl), d, dl)              # 长度数字右对齐放在 h[1..3] 区域
k = h[0] = RandomNext(0x20, 0x7E)
f = h[1]

if f == 0x20:                            # 首次调用（dl < 3 时 h[1] 未被覆盖）
    if k 为奇数: k++                     # 强制 k 偶数
    f = RandomNext(0x20, 0x7E)           # 随机 filler
elif k 为偶数:                           # 非首次调用（dl == 3 时 h[1] = d[0]）
    k++；若 k > 0x7E 则 k = 0x21         # 强制 k 奇数

swap(h[2], h[3])                         # 长度数字字节交换

if frame_tn_ 已置位:
    返回 h[0..3]（4 字节简单头）
else:
    K = inet_chksum(h, 4) ^ length
    N = (K + KF_MOD) % MOD
    d = base94_decimal(N)
    校验 d.size() == 3，否则失败
    memcpy(h + 4, d, 3)
    shuffle_data(h + 4, 3, kf)           # 校验和数字 shuffle
    frame_tn_ = true                     # 此后发送方切简单头
    返回 h[0..6]（7 字节扩展头）
```

**奇偶性机制（关键）**：`k` 的奇偶性编码了 `f` 的语义——
- `dl < 3`（长度数字未占满 h[1..3]）：`k` 必为**偶数**，`f` 是随机 filler，解码端忽略；
- `dl == 3`（长度数字占满 h[1..3]，`f = d[0]`）：`k` 必为**奇数**，`f` 是长度数字的一部分，解码端保留。

### 4.2 帧头解析

**恢复规范形** `base94_decode_kf`（`ITransmission.cpp:394-403`）：

```
if k 为偶数: f = 0x20                    # 丢弃 filler
k = 0x20                                 # 恢复种子字节
swap(h[2], h[3])                         # 撤销字节交换
```

**长度解码** `base94_decode_length`（`ITransmission.cpp:384-389`）：

```
N = base94_decimal(h + 1, 3)             # 固定读 3 字节（前导 0x20 视为 0）
length = (N - KF_MOD + MOD) % MOD
```

**首帧扩展头校验** `base94_decode_length_r1`（`ITransmission.cpp:521-554`）：

```
读 7 字节
K = inet_chksum(h, 4)
base94_decode_kf(h)
payload_length = base94_decode_length(h + 1, kf)     # 校验 payload_length >= 1
unshuffle_data(h + 4, 3, kf)
N = base94_decimal(h + 4, 3)
校验 N == (K ^ payload_length)，否则失败（篡改检测）
frame_rn_ = true                        # 此后接收方切简单头
```

**后续帧** `base94_decode_length_rn`（`ITransmission.cpp:496-516`）：读 4 字节 → `base94_decode_kf` → 长度解码。

### 4.3 完整帧组装

**发送** `base94_encode`（`ITransmission.cpp:405-437`）：

```
payload = base94_encode(data, datalen, kf)          # §2.6，outlen 为编码后长度
header  = base94_encode_length(outlen, kf)          # §4.1
packet  = header || payload
```

**接收** `base94_decode`（`ITransmission.cpp:570-607`）：

```
payload_length = base94_decode_length(...)          # §4.2，先 7 字节后 4 字节
校验: 1 <= payload_length <= EVP_BASE94_MAX_FRAME (131136)
读 payload_length 字节
decoded = base94_decode(payload, payload_length, kf)
```

**内存内解码** `base94_decode`（`ITransmission.cpp:439-491`，用于 `Decrypt()` 路径）额外校验：`payload_length + 4 == datalen`（完整性）。

---

## 5. 二进制帧（握手后，非 plaintext 模式）

### 5.1 帧头加密 `Transmission_Header_Encrypt`（`ITransmission.cpp:616-665`）

```
payload_len--                              # 65536 → 65535，避免 0 长度
array[3] = { seed, payload_len >> 8, payload_len & 0xFF }
seed = RandomNext(0x01, 0xFF)
header_kf = kf ^ seed

if protocol_cipher 存在:
    array[1..2] = protocol_cipher.Encrypt(array[1..2])   # 2 字节，输出必须仍为 2 字节

array[1] ^= header_kf; array[2] ^= header_kf            # 逐字节 XOR
shuffle_data(array + 1, 2, header_kf)
output = delta_encode(array, 3, kf)                     # §2.4，输出 3 字节
```

### 5.2 帧头解密 `Transmission_Header_Decrypt`（`ITransmission.cpp:670-705`）

```
array = delta_decode(header, 3, kf)
header_kf = kf ^ array[0]
unshuffle_data(array + 1, 2, header_kf)
array[1] ^= header_kf; array[2] ^= header_kf
if protocol_cipher 存在:
    array[1..2] = protocol_cipher.Decrypt(array[1..2])
len = (array[1] << 8) | array[2]
return len + 1
```

### 5.3 负载变换 `Transmission_Payload_Encrypt`（`ITransmission.cpp:729-758`）

```
safest = !handshaked_                     # 握手前强制全变换

if safest || key.masked:
    masked_xor_random_next(data, data + datalen, header_kf)   # §2.5
if safest || key.shuffle_data:
    shuffle_data(data, datalen, header_kf)                    # §2.3
if safest || key.delta_encode:
    output = delta_encode(data, datalen, key.kf)              # 注意用 key.kf 而非 header_kf
else:
    output = copy(data, datalen)
```

解密 `Transmission_Payload_Decrypt`（`ITransmission.cpp:782-805`）为逆序逆操作：先 `delta_decode`（若启用），再 `unshuffle_data`，再 `masked_xor_random_next`（XOR 自逆，顺序无关）。

### 5.4 完整包加密 `Transmission_Packet_Encrypt`（`ITransmission.cpp:835-889`）

```
if protocol_cipher 且 transport_cipher:
    payload = transport_cipher.Encrypt(data, datalen)         # 长度不变
    header  = Header_Encrypt(payload_len)                     # §5.1
    payload = Payload_Encrypt(header_kf, payload)             # §5.3
else:
    header  = Header_Encrypt(datalen)
    payload = Payload_Encrypt(header_kf, data)
packet = header || payload
```

### 5.5 完整包解密 `Transmission_Packet_Decrypt`（`ITransmission.cpp:894-946`）

```
校验 datalen > 3
payload_len = Header_Decrypt(data)                            # §5.2
校验 1 <= payload_len <= PPP_BUFFER_SIZE (65536)
校验 payload_len + 3 == datalen                              # 截断攻击检测
payload = Payload_Decrypt(header_kf, data + 3, payload_len)
if transport_cipher 存在:
    payload = transport_cipher.Decrypt(payload)
```

### 5.6 流式读取 `Transmission_Packet_Read`（`ITransmission.cpp:951-1004`）

读 3 字节头 → 解码长度 → 校验上限 → 读 `payload_len` 字节 → 解密（同 §5.5，无长度一致性校验，因为长度来自流）。

---

## 6. 数据面调度（Encrypt / Decrypt / Read / Write）

### 6.1 发送路径 `ITransmissionBridge::Encrypt`（`ITransmission.cpp:130-148`）

```
packet = EncryptBinary(data, datalen)          # §5.4（safest = !handshaked_）
if !handshaked_ || key.plaintext:
    packet = base94_encode(packet, kf)         # §4.3 加 base94 外壳
```

### 6.2 接收路径 `ITransmissionBridge::Decrypt`（`ITransmission.cpp:153-181`）

```
if !handshaked_ || key.plaintext:
    packet = base94_decode(data, kf)           # §4.3 内存版
    packet = DecryptBinary(packet)             # §5.5
else:
    packet = DecryptBinary(data)
```

### 6.3 流式读 `ITransmissionBridge::Read`（`ITransmission.cpp:186-209`）

```
if !handshaked_ || key.plaintext:
    packet = base94_decode(流式)               # §4.3
    packet = DecryptBinary(packet)
else:
    packet = ReadBinary(流式)                  # §5.6
```

### 6.4 流式写 `ITransmissionBridge::Write`（`ITransmission.cpp:232-319`）

`Encrypt`（§6.1）→ 底层 socket 写。零长度输入拒绝（`ITransmission.cpp:290-293`）。

---

## 7. 握手协议

### 7.1 NOP 前奏 `Transmission_Handshake_Nop`（`ITransmission.cpp:1226-1248`）

```
kl = 1 << key.kl        # 默认 1024
kh = 1 << key.kh        # 默认 4096
if kl > kh: swap(kl, kh)
rounds = (kl == kh) ? kl : RandomNext(kl, kh)     # 闭区间
rounds = ceil(rounds / (175 << 3))                # 除以 1400，默认得 1..3
for i in 0..rounds-1:
    发送 dummy session-id 包（session_id = 0，见 §7.2）
```

作用：连接建立初期产生随机数量的纯噪声包，抗主动探测与流量指纹。

### 7.2 session-id 包构造 `Transmission_Handshake_Pack_SessionId`（`ITransmission.cpp:1012-1082`）

```
if session_id != 0:                       # 真实包
    kfs[0] = RandomNext(0x00, 0x7F)       # MSB=0
    id_str = decimal(session_id)          # Int128 十进制字符串
else:                                     # dummy 包
    kfs[0] = RandomNext(0x80, 0xFF)       # MSB=1
    id_str = decimal(随机 128 位)          # 4 次 RandomNext() 拼成

kfs[1..3] = RandomNext(0x01, 0xFF) × 3
id_str += RandomNext(0x20, 0x2F)          # 分隔符（0x20..0x2F）

# 随机 padding（抗流量分析）
max = key.kx % 0x100                      # 默认 128
if max > 0:
    id_str += max 个 RandomNext(0x20, 0x7E)
    id_str += '/'
    min = id_str.size() + 4
    if min > max: max = min
    loops = RandomNext(1, max << 2)
    id_str += loops 个 RandomNext(0x20, 0x7E)

# 加密：4 轮 XOR，每轮密钥 = 配置 kf 异或一个 kfs 字节
kf = key.kf
for i in 0..3:
    kf ^= kfs[i]
    for j in 0..id_str.size()-1:
        id_str[j] ^= kf

packet = kfs(4 字节) || id_str
```

### 7.3 session-id 包解析 `Transmission_Handshake_Unpack_SessionId`（`ITransmission.cpp:1087-1128`）

```
校验 packet_length >= 4
if packet[0] & 0x80:                      # dummy，标记 eagin=true 并跳过
kfs = packet[0..3]
按 §7.2 相同 4 轮 XOR 解密剩余字节
sid = Int128FromString(解密文本, 10)      # 解析失败 → SessionIdInvalid
```

### 7.4 客户端握手 `InternalHandshakeClient`（`ITransmission.cpp:1441-1528`）

```
1. Nop 前奏（§7.1）
2. sid = 读 session-id 包（跳过 dummy，循环直到真实包）      # 服务端会话标识
3. ivv = GuidStringToInt128(随机 GUID)                       # 128 位随机数
4. 发送 ivv 包
5. nmux = 读 session-id 包
6. mux = (nmux & 1) != 0                                     # 最低位协商多路复用
7. canary 校验（§7.6）：nmux 高 64 位若匹配 magic 则必须等于本地 canary，否则 ObfuscationFlagsMismatch
8. 若配置了双 cipher：重建 protocol_/transport_（§7.7）
9. handshaked_ = true
```

### 7.5 服务端握手 `InternalHandshakeServer`（`ITransmission.cpp:1533-1601`）

```
1. Nop 前奏（§7.1）
2. 发送 session_id 包（上层提供的会话标识）
3. nmux = MAKE_OWORD(随机低 64 位, canary 高 64 位)
   若 mux 请求: 使 nmux 为奇数（while (nmux & 1) == 0: nmux++）
   否则:       使 nmux 为偶数（while (nmux & 1) != 0: nmux++）
4. 发送 nmux 包
5. ivv = 读 session-id 包
6. 若 ivv != 0：重建双 cipher（§7.7），handshaked_ = true
```

### 7.6 混淆标志 canary `Transmission_Handshake_FlagCanary`（`ITransmission.cpp:1209-1221`）

```
magic = 0xC0DEC0DEC0DE
flags = masked | (plaintext << 1) | (delta_encode << 2) | (shuffle_data << 3)
kf_canary = (uint32)kf & 0xFFF
canary = magic | (flags << 48) | (kf_canary << 52)
```

客户端校验（`ITransmission.cpp:1469-1498`）：`nmux_high = nmux >> 64`；若 `(nmux_high & 0x0000FFFFFFFFFFFF) == 0xC0DEC0DEC0DE`（2^-48 碰撞概率），则要求 `nmux_high == 本地 canary`，否则握手失败并报 `ObfuscationFlagsMismatch`。不匹配 magic 视为旧版对端，静默跳过（向后兼容）。

### 7.7 会话密钥重建（`ITransmission.cpp:1500-1521`、`1566-1589`）

```
ivv_str = decimal(ivv, 32)                # 32 进制字符串
if ivv > 0: ivv_str = "+" + ivv_str       # 正数加 '+' 前缀

protocol_  = Ciphertext(key.protocol, key.protocol_key + ivv_str)
transport_ = Ciphertext(key.transport, key.transport_key + ivv_str)
```

**Ciphertext 构造**（`Ciphertext.cpp:16-25`）：
- 若 `EVP::Support(method)`（OpenSSL `EVP_get_cipherbyname` 非空，`EVP.cpp:247-264`）→ EVP 后端；
- 否则若 `RC4::Support(method)`（`rc4-md5`/`rc4-sha1`/`rc4-sha224`/`rc4-sha256`/`rc4-sha384`/`rc4-sha512`，`rc4.cpp:336-351`）→ RC4 后端。

**EVP 后端**（`EVP.cpp:272-316`）：
```
key, iv = EVP_BytesToKey(cipher, EVP_md5(), salt=NULL, password, 1 轮)
iv_string = "Ppp@" + method + "." + raw_key_bytes + "." + password
iv = MD5(iv_string)                       # 二进制 16 字节
rc4_crypt(key, keylen, iv, ivlen, 0, 0)   # 用自定义 RC4 再搅一次 IV（§2.9）
```
加密/解密用 `EVP_CipherInit_ex` + `EVP_CipherUpdate`，CFB 模式长度不变，无 padding 输出（`EVP.cpp:113-134`）。

**RC4 后端**（`rc4.cpp:252-270`）：
```
sbox_key = hash_hmac(password, algorithm, hex=false)   # 二进制摘要
rc4_sbox_descending(sbox, 255, sbox_key)               # 降序初始化
```

### 7.8 自定义 RC4 变体（`rc4.cpp:86-241`）

S-box 长度 **255**（非 256）。KSA 与标准相同但模 255；初始化支持升序/降序填充。

PRGA 变体 `rc4_crypt_sbox_c`（`rc4.cpp:195-224`，RC4 类加密用此版本）：

```
x = E ? subtract : -subtract             # RC4 类默认 subtract=0, E=0 → x=0
for i in 0..datalen-1:
    low  = (low + keylen) % 255          # 步进 = keylen（非标准）
    high = (high + sbox[i % 255]) % 255
    swap(sbox[low], sbox[high])
    mid  = (sbox[low] + sbox[high]) % 255
    if E: data[i] = (data[i] ^ sbox[mid]) - x
    else: data[i] = (data[i] - x) ^ sbox[mid]
```

`rc4_crypt_sbox`（`rc4.cpp:149-181`）为 `low` 恒 0 的变体，仅用于 IV 搅动（`EVP.cpp:314`）。RC4 的 Encrypt/Decrypt 相同（流密码对称，`rc4.cpp:327-329`）。

---

## 8. 完整复现清单

按以下顺序实现即可得到一个字节级兼容的对端：

1. **原语层**：§2.1 PRNG、§2.3 shuffle、§2.4 delta、§2.5 masked XOR、§2.6 base94 字节编解码、§2.7 base94 整数、§2.8 checksum。
2. **密码层**：§7.8 自定义 RC4（255 S-box）+ §7.7 EVP/RC4 后端与密钥派生。
3. **帧层**：§4 base94 帧（含奇偶性机制与首帧扩展头）、§5 二进制帧（头加密 + 负载变换 + 双 cipher）。
4. **握手层**：§7.1 NOP → §7.2/7.3 session-id 包 → §7.4/7.5 双向序列 → §7.6 canary → §7.7 密钥重建。
5. **数据面**：§6 的 Encrypt/Decrypt/Read/Write 调度。

### 8.1 实现陷阱清单

| # | 陷阱 | 说明 |
|---|------|------|
| 1 | base94 帧头奇偶性 | `dl<3` 时 k 必须偶数、f 为 filler；`dl==3` 时 k 必须奇数、f 是长度数字。见 §4.1 |
| 2 | 首帧扩展头 | 双方各自维护 `frame_tn_`/`frame_rn_` 标志，**发送首帧**用 7 字节头并置位，**接收首帧**读 7 字节校验后置位。收发独立 |
| 3 | 长度减一 | 二进制帧头编码前 `payload_len--`，解码后 `+1`（§5.1/5.2） |
| 4 | 负载变换用 `header_kf`，delta 用 `key.kf` | `masked_xor`/`shuffle` 的密钥是 `kf ^ seed`，`delta_encode` 的密钥是配置 `key.kf`（§5.3） |
| 5 | safest 模式 | 握手前（`!handshaked_`）强制全部变换，忽略配置开关（§5.3） |
| 6 | base94 帧上限 | 接收端允许 `payload_length <= 131136`（2×65536+64），解码后由二进制解密路径再限 65536（§4.3、§5.5） |
| 7 | 二进制帧长度一致性 | 内存解密路径校验 `payload_len + 3 == datalen`；流式路径不校验（§5.5/5.6） |
| 8 | ivv 字符串前缀 | `ivv > 0` 时加 `'+'`，负数不加（§7.7） |
| 9 | nmux 奇偶 | 服务端按 mux 请求强制 nmux 最低位（§7.5）；客户端 `mux = nmux & 1` |
| 10 | dummy 包跳过 | 客户端读 session-id 时循环跳过 MSB=1 的包（§7.3/7.4） |
| 11 | canary 向后兼容 | 高 64 位不匹配 magic 时静默跳过校验（§7.6） |
| 12 | RC4 模 255 | 所有 PRGA 取模是 255 不是 256；`low` 步进是 keylen（§7.8） |
| 13 | 帧切换原子性 | `frame_tn_` 在发送扩展头**之后**置位；`frame_rn_` 在扩展头校验**通过后**置位（§4.1/4.2） |
| 14 | 零长度拒绝 | 数据面 Write/Encrypt 拒绝 `datalen == 0`（§6.4） |

---

## 9. 抗封锁设计原理（对应关系）

| 对抗目标 | 机制 | 位置 |
|----------|------|------|
| DPI 识别加密流量特征 | 握手前全部流量为可打印 ASCII（base94） | §4 |
| 固定特征指纹 | 帧头随机种子、随机 filler、长度混淆、字节交换、shuffle | §4.1、§5.1 |
| 主动探测（连接即发特征包） | NOP 噪声前奏 + dummy 包 | §7.1、§7.2 |
| 流量分析（包长/时序） | 随机 padding、随机轮数、随机包长 | §7.2、§7.1 |
| 会话关联（多连接指纹相同） | 每连接 ivv 派生独立工作密钥 | §7.7 |
| 篡改/重放 | 首帧校验和（`inet_chksum ^ length`）、帧长一致性校验 | §4.2、§5.5 |
| 配置不一致导致静默断连 | canary 显式报错 | §7.6 |