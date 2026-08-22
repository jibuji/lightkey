# 加密规格（crypto）

- 状态：已拍板（D4）
- 关联：[data-model.md](data-model.md)（密文容器使用处）· [recovery.md](recovery.md)（信封密钥）
  · [audit.md](audit.md)（审计 HMAC 密钥）

## 1. 设计目标

- **零知识彻底**：主密码不出客户端；存储端（BYO 云）只见密文。
- **密钥互不复用**：数据加密与审计 HMAC 两把功能密钥由 HKDF 分叉，恢复信封
  密钥由恢复码独立派生；互不可推导、互不可替代。
- **格式自描述**：密文 blob 内嵌格式类型与版本号，支持演进与迁移。
- **刻意不同于 Bitwarden**：Bitwarden 用 CBC + HMAC 组合（AES-256-CBC +
  HMAC-SHA256）；我们**只用 AES-256-GCM**（AEAD），这是拍板决定，勿改。

## 2. 密钥层级

```
主密码（用户输入）
   │  Argon2id(m=64MiB, t=3, p=4, salt=16B 随机)
   ▼
主密钥 MK（32B）
   │  HKDF-SHA256（各自独立 info 标签，提取一次、扩展两次，互不复用）
   ├──▶ 数据加密密钥 K_data    —— 加密全部条目/索引/附件 blob
   └──▶ 审计 HMAC 密钥 K_audit  —— 审计日志防篡改（见 audit.md）

恢复信封密钥 K_recovery **不在** MK 分叉之内：由恢复码 + Argon2id 独立派生
（见 [recovery.md](recovery.md) §3）。
```

- 主密钥 **永不明文落盘**；磁盘上主密钥的持久副本仅存在于**恢复信封**中
  （用 K_recovery 加密，见 [recovery.md](recovery.md)）。
- 解锁后 K_data / K_audit 只存在于守护进程内存（[ipc.md](ipc.md)），锁定即擦除
  （实现用 `zeroize`）；K_recovery 仅在生成/重加密恢复信封时由恢复码临时派生，
  用后即擦除（见 [recovery.md](recovery.md) §3）。

### KDF 参数（固定）

| 参数 | 值 | 说明 |
|------|-----|------|
| 算法 | Argon2id | 抗 GPU/ASIC 的现代选择 |
| m | 64 MiB | 内存代价 |
| t | 3 | 时间代价 |
| p | 4 | 并行度 |
| salt | 16B 随机 | 每个库唯一，存于 vault 头 |
| 输出 | 32B | 主密钥 MK |

> 参数作为 KDF 参数的**可演进字段**写入 vault 头（见 §4），未来提升代价无需迁移数据。

## 3. 原语清单

| 用途 | 原语 | 说明 |
|------|------|------|
| 主密钥派生 | Argon2id (64MiB,3,4) | 主密码 → MK，见 §2 |
| 恢复信封密钥派生 | Argon2id（信封内独立 salt） | 恢复码 → K_recovery，见 recovery.md §3 |
| 密钥分叉 | HKDF-SHA256 | K_data / K_audit 两把密钥各自独立 info |
| 数据加密 | AES-256-GCM | AEAD；随机 12B nonce 每次加密重新生成 |
| 审计防篡改 | HMAC-SHA256 | K_audit；见 audit.md |
| 随机源 | CSPRNG（`rand` / 平台） | salt、nonce、条目/附件密钥、会话令牌 |

## 4. 文件与 blob 格式

所有落盘结构遵循同一约定：**magic/版本打头、KDF 参数可演、载荷自描述**。

### 4.1 Vault 头（`vault.json`，库级）

```jsonc
{
  "format": "lightkey.vault",        // 格式类型（magic 域名）
  "version": 1,                       // 格式版本号
  "kdf": {
    "algorithm": "argon2id",
    "m": 67108864, "t": 3, "p": 4,    // 64MiB
    "salt": "<base64, 16B>"           // 随机 16B
  },
  "ciphertext_format": { "type": "aes-256-gcm", "version": 1 },
  "recovery_envelope_ref": "recovery.envelope",  // 见 recovery.md
  "created": "<ISO-8601>"
}
```

- vault 头**不含明文元数据**（库名等如需可见，另以最小明文文件承载，仍不泄漏内容信息）。
- `salt` 每次 `init` 随机生成。

### 4.2 自描述密文容器（条目/索引/附件/信封通用）

```
┌────────────┬──────────┬─────────────┬──────────────┬──────────────┐
│ magic (4B) │ ver (1B) │ type (1B)   │ nonce (12B)  │ ciphertext+ │
│ "LKC1"     │ 0x01     │ item/index/ │ 随机          │ GCM tag      │
│            │          │ attach/env/ │              │ (AAD 按需)   │
│            │          │ tomb/chunk/ │              │              │
│            │          │ check/rule  │              │              │
└────────────┴──────────┴─────────────┴──────────────┴──────────────┘
```

- **AAD**：解密必须校验的关联数据——类型 + 对象 id（条目/附件 id），防换位。
- 小对象（条目、索引、信封）整体单段加密；附件按 [data-model.md](data-model.md) 分块。
- 版本号升级路径：`version` 递增 + 迁移文档，见 [decisions.md](decisions.md) 约定。

### 4.3 明文边界

存储端（BYO 云/目录）可见的最小集合，仅此而已：

- 密文文件（条目/索引/附件/信封）
- 文件名 = 对象 id（纯 UUID，无时间戳——同步排序依据加密索引内 revisionDate，见 [data-model.md](data-model.md) §2）
- vault 头（不含任何内容明文）

**索引/清单文件同样整体加密**（D6）：存储端永远看不到条目名、类型、数量明细。

## 5. 实施注意（M0 起）

- 用 `zeroize` 擦除主密钥与派生密钥（Drop 实现）。
- 每次加密必须重新生成 nonce；同 nonce 同密钥复用即泄露（GCM 灾难性失败）。
- 解密失败按“密文被篡改或密钥错误”统一处理，不区分错误类型（防 oracle）。
- 属性测试：加密往返、nonce 唯一性抽样、密文任意字节翻转 → 解密失败
  （见 [testing.md](testing.md)）。
