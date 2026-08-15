# 数据模型规格（data-model）

- 状态：已拍板（D5/D6）
- 关联：[crypto.md](crypto.md)（密文容器）· [sync.md](sync.md)（增量/墓碑/CAS）
  · [recovery.md](recovery.md)（信封为一种对象）

## 1. 总原则

- **条目级密文 blob**：每条目独立加密（K_data），独立文件。
- **加密索引**：条目清单/索引整体加密；存储端只见密文文件与文件名时间戳（D6）。
- **增量同步**：靠 `revisionDate`；**乐观并发**：CAS，整条目 last-write-wins（D5）。
- **软删除**：删除 = 写墓碑，30 天延迟硬删（D5）。

## 2. 对象类型

| 对象 | 文件 | 加密 | 说明 |
|------|------|------|------|
| 条目 item | `{uuid}.item.lk` | K_data | 见 §3 |
| 索引 index | `index.lk` | K_data | 条目清单（id、revisionDate、类型标签等最小可索引字段，全部在密文内） |
| 墓碑 tombstone | `{uuid}.tomb.lk` | K_data | 软删除标记，含删除时间 |
| 附件附件元数据 | `{uuid}.attach.lk` | K_data | 附件清单 + 每附件密钥（**加密的**）与分块引用 |
| 附件分块 | `{uuid}.{i}.chunk.lk` | 每附件独立密钥 | 1 MiB/块（见 §5） |
| 恢复信封 | `recovery.envelope` | K_recovery | 主密钥副本（见 recovery.md） |

- 文件名中的对象 id 为 UUID v4；时间戳后缀仅用于同步排序，不含内容信息。

## 3. 条目 schema（参照 Bitwarden login/secureNote 映射，D5）

条目密文内部为 JSON（JSON-RPC 同款 serde），`type` 决定字段集：

```jsonc
{
  "id": "<uuid>",
  "type": "login | secureNote",          // V1 只做这两类（Bitwarden 映射）
  "name": "示例",
  "revisionDate": "<ISO-8601>",
  "deleted": false,                       // true = 墓碑态（见 §4）
  "favorite": false,
  "login": {                              // type=login 时
    "username": "user@example.com",
    "password": "s3cr3t",                 // 条目密文内，明文字段仅存在于解密态
    "uris": ["https://example.com"],      // 可多个
    "totp": null                          // V1 不实现 TOTP，字段保留 null
  },
  "secureNote": { "note": "..." },        // type=secureNote 时
  "customFields": [ { "name": "...", "value": "...", "hidden": true } ],
  "attachments": [ /* 附件元数据引用，见 §5 */ ]
}
```

- **映射依据**：Bitwarden 的 `login`（username/password/uris/totp）与
  `secureNote`（notes）为 V1 字段集；`card`/`identity` 等类型 V1 不做。
- 自定义字段（customFields）保留，hidden 字段在 UI 中遮罩。

## 4. 修订、墓碑与并发（D5）

### 4.1 revisionDate

- 条目每次变更（新建/编辑/软删）更新 `revisionDate`（客户端本地时钟，ISO-8601）。
- 同步以 revisionDate 做增量：仅交换“比我新的条目”（见 [sync.md](sync.md)）。
- 时钟偏移风险由 CAS 兜底（见 4.3）。

### 4.2 软删除与 30 天延迟硬删

- 删除条目 → 写墓碑（`tomb.lk`，含 `deletedAt`），条目本身在**本地与远端**
  均保留密文至硬删点，保证可恢复。
- 硬删：墓碑存在 ≥ 30 天且同步确认后，删除条目 + 墓碑 + 附件密文。
- 墓碑也参与同步（保证删除在多端传播）；硬删前若对端仍持旧条目，按
  last-write-wins 收敛规则处理（见 [sync.md](sync.md)）。

### 4.3 乐观并发（CAS）

- 客户端上传条目时携带 **base revision**（自己上次见到的该条目 revision）。
- 服务端（BYO 存储以 CAS 语义实现，WebDAV 用 `If-Match`/ETag，S3 用
  `If-Match` 或条件写）校验：base revision == 存储端当前 revision 才写入；
  不匹配 → **CAS 冲突**，整条目 last-write-wins（revisionDate 更新者胜，
  并保留字段级合并留口：V1 整条目覆盖，不做字段合并）。
- 冲突处理：客户端重拉最新条目，若本地更新更晚则重试上传；否则放弃本地覆盖。

## 5. 附件（D5）

- 每附件**独立密钥**（K_attach，随机 32B，由 K_data 派生的附件密钥容器保护），
  附件密文**绝不复用条目密钥**。
- 附件按 **1 MiB 流式分块**：`{uuid}.{i}.chunk.lk`，每块独立 nonce + AAD
  （附件 id + 块号），支持断点续传与按需下载（V1 桌面端可先整包下载，协议支持分块）。
- 附件元数据（`attach.lk`）内含：文件名、MIME、大小、块数、每块引用、
  加密的 K_attach。
- 附件同样受 revisionDate / CAS 管辖（整附件版本化）。

## 6. 加密索引

- `index.lk` 整体加密（K_data），内容为条目最小索引：`id`、`revisionDate`、
  `type`、`deleted`（供列表/增量/墓碑判断）。
- 客户端本地始终有解密态索引缓存；索引用于变更发现与增量拉取（[sync.md](sync.md)），
  **不**向存储端暴露任何明文。
- 索引损坏 → 全量重建（扫描本地条目密文重建），不阻塞解锁。

## 7. 实施注意（M0 起）

- 所有时间戳统一 ISO-8601 UTC；比较用同一时区基准，避免增量漏判。
- 条目不变量（property test）：revisionDate 单调不减；墓碑只增不改；id 唯一。
- schema 变更走密文容器版本号 + 迁移（见 [crypto.md](crypto.md) §4.2）。
