# LightKey M1 同步 Review 报告

- 对象：PR #10（`fm/lightkey-m1-core`，head `f13f2da`，base=main，15 文件 +5264/−38）
- 审查基准：`docs/sync.md`、`docs/data-model.md` §4/§6、`docs/cli.md` §3、`docs/ipc.md`、`docs/decisions.md`
- 验证基线（修复前）：`cargo fmt --check` 干净；`clippy -D warnings` 干净；
  `cargo test -p lk-core -p lk-cli` 62+8+1 全过；`e2e_m0.sh` 41/41；`e2e_m1.sh` 38/38。
- 修复后：`cargo test` 64+8+1 全过；`e2e_m0.sh` 41/41；`e2e_m1.sh` 38/38；
  fmt/clippy 干净。Windows 交叉检查沿用项目既定约定由 CI（windows-latest 原生）
  承担（本地 Linux 无 MSVC 的 ring 构建工具链）。

结论：**无 S1 严重项**。发现 2 项 G2（已当场修复）与 1 项 G1（已缓解 + 记录残留），
另有 4 项 A 级建议与若干低优先级说明。修复提交追加到 `fm/lightkey-m1-core`。

---

## 分级说明

- S1：安全 / 数据丢失 / 正确性严重问题（需修复或 needs-decision）
- G1：重要（正确性 / 并发 / 规格一致性，应修）
- G2：一般缺陷（可修复的边界/缺陷）
- A1–A4：建议 / 边缘 / 文档

---

## G1 —— 后台轮询持守护进程互斥锁，同步期间阻塞全部 IPC

- 位置：`crates/lk-cli/src/main.rs:1455-1473`（`cmd_daemon` 轮询线程）
- 现象：请求处理与后台轮询共用 `Arc<Mutex<Daemon>>`。`sync_round()` 在**持锁期间**
  执行网络 I/O（`fetch_remote_index`/`pull_entry`/`push_entry`，单请求超时 60s）。
  轮次期间任何 `lk` 命令（`item.*`/`unlock`/`lock`…）都会阻塞在 `state.lock()`。
  网络停滞时（规格 §5 明确要覆盖的失败场景）可阻塞数十秒到数分钟。
- 规格依据：`docs/sync.md` §2「静默轮询：后台进行，不打断用户操作」。
- 处理：**已缓解**——轮询线程改用 `try_lock()`，有前台请求在服务时跳过本轮让路
  （`TryLockError::WouldBlock => continue`）；毒化锁（进程退出）时终止线程。
  见 `main.rs:1458-1464`。
- 残留（如实记录）：缓解不根治——本轮拿到锁后若网络停滞，期间到达的前台请求
  仍会等待。彻底修复需把同步引擎重构为「网络 I/O 期间不持锁」（抓取/应用两阶段），
  属较大范围改动，未在本轮擅自动工。建议作为 M1 后置跟进项或交船长裁决。

---

## G2 —— S3 SigV4 签名两处错误（已修复 + 回归测试）

文件：`crates/lk-core/src/storage.rs`

### G2-a 列表查询串二次编码 → 签名与请求不一致

- 位置：原 `list()`（`storage.rs:1052-1060`）+ 原 `send()` 内 `canonical_query_string`
- 现象：`list()` 先 `uri_encode_query(prefix/token)` 预编码，`send()` 再经
  `canonical_query_string` 二次编码（`%` → `%25`）。含特殊字符的 prefix（空格/中文等）
  或分页 `continuation-token`（S3 返回的 token 常含 `+/=`）时，canonical query 与
  实际请求 URL 不一致 → AWS 返回 403 SignatureDoesNotMatch。>1000 对象分页必触发。
- 修复：新增 `s3_query_string(&[(k,v),…])`，逐项编码恰好一次 + 排序，canonical 与
  URL 同源；删除 `canonical_query_string`。见 `storage.rs:889-905`、`send()` `storage.rs:774-777`。

### G2-b path-style 列表 canonical URI 缺 `/bucket/` 段

- 位置：原 `send()` key=None 分支返回 `("/", url)`（`storage.rs:738-744`）
- 现象：path-style（MinIO 等 S3 兼容自定义 endpoint，本项目「S3 兼容」主场景）
  的 ListObjectsV2 请求实际路径为 `/bucket/`，但 canonical URI 写成 `/`，
  SigV4 签名与请求路径不一致 → 403。虚拟主机风格（AWS 默认）不受影响。
- 修复：新增 `list_canonical_uri(bucket, path_style)`：path-style 返回 `/bucket/`，
  虚拟主机返回 `/`。见 `storage.rs:875-882`、`storage.rs:746`。

回归测试：`s3_query_string_encodes_once_and_sorts`（`storage.rs:1723`）、
`list_canonical_uri_path_style`（`storage.rs:1741`）。

---

## A 级建议

### A1 —— 「文件名时间戳」规格内部矛盾（未改 docs，待 needs-decision）

- 位置：`docs/data-model.md` §2 表（`{uuid}.item.lk` 无时间戳）与散文
  「时间戳后缀仅用于同步排序」矛盾；`docs/sync.md` §1「只见密文文件 + 文件名
  时间戳（D6）」；`docs/milestones.md` M1 同款表述。
- 实现选择：纯 UUID 文件名（无时间戳），同步排序依据加密索引内 revisionDate
  （`crates/lk-core/src/sync.rs:28-30` 头注释）。这更贴合 D6「零知识彻底」
  （文件名时间戳会向存储端泄漏修改时间）。
- 建议：规格散文与表不一致属**规格事实矛盾**，按约束需 needs-decision 修订 docs；
  本报告只登记，未改 docs。实现本身可辩护且可合并。

### A2 —— 同 revision 不同内容的收敛盲区（理论边缘）

- 位置：`crates/lk-core/src/sync.rs:163`（`lww` 内容哈希决胜）、`diff`（`sync.rs:665`）
- 现象：`lww` 对「同 revision」做了内容 SHA-256 确定性决胜，但 `diff` 只把
  「revision 不同」或「revision 相同且 deleted 不同」路由到拉取/推送；同 revision
  且同 deleted 但内容不同时两者都不触发，内容哈希决胜在该路径不可达（仅 CAS 冲突
  路径可达）。触发需两独立客户端在同一微秒编辑同一条目，概率极低。
- 建议：记录为已知边界（时钟微秒碰撞）；完整修复需在 diff 层解密比对内容，
  与「仅拉差异条目」优化冲突，暂不修。

### A3 —— S3 `put` 返回合成 ETag（潜在脆弱，当前无功能影响）

- 位置：`crates/lk-core/src/storage.rs:1018`（`S3Backend::put`）
- 现象：写入成功后返回 `Written { etag: 期望值或 Sha256(data) }`，而非服务端真实
  ETag。当前同步引擎**从不使用**该返回值（每次 `put` 前都 `etag()`/`get()` 重新读取
  真实 ETag），故无功能影响；但返回值语义误导，未来调用方误用会破坏 CAS。
- 建议：改为从 PUT 响应头提取真实 ETag（缺省回退合成值）。

### A4 —— 测试-only `unsafe` transmute

- 位置：`crates/lk-core/src/sync.rs:765-769`（`seed_vault()` 的 thread_local TempDir）
- 说明：把 `&TempDir` transmute 为 `&'static`，安全性依赖 thread_local 存活的种子
  目录在测试进程内不析构。仅测试代码，生产代码无新增 unsafe（M1 新增 unsafe 仅此一处，
  其余 unsafe 均属 M0 既有的 libc/Windows named pipe）。可接受，但脆弱。

---

## 低优先级说明（未改，登记备查）

1. `purge_phase` 的 `None if pushed_ids.contains(&id)` 分支（`sync.rs:628`）为死代码：
  已删除条目缺远端时 `diff` 不推送（`sync.rs:691-694`），故该组合不可达；防御性保留无害。
2. `pull_attachment`（`sync.rs:432`）在分块循环内重复派生 K_attach（每块一次），
  可提至循环外（微效率，无正确性问题）。
3. `import_attachment`（`vault.rs:318`）未显式校验 `meta.id == aid`；由密封 AAD
  绑定兜底（`sealed_key` 以 `meta.id` 为 AAD，读取以 `aid` 为 AAD，不匹配即
  `SyncAnomaly`），仅恶意同钥端构造 `chunks=0` 时才有理论缝隙。
4. LWW 时钟偏移经 `import_item` 提升 `last_revision`（`vault.rs:288`）会被放大
  传播：单端时钟超前会使其 revision 永久领先。属 last-write-wins + 本地时钟的
  设计已知属性（`data-model.md` §4.1「时钟偏移风险由 CAS 兜底」）。
5. `store_sync_credentials`（`daemon.rs`）以 URL 为 keyring 键，换 URL 后旧凭据残留；
  `WebDav.auth`（Basic base64 串）未 zeroize（守护进程内存内，可接受）。
6. `Cargo.toml` 存在重复注释行 `# --- M1 同步（BYO 存储：WebDAV / S3）---`（纯排版）。
7. 手工改坏 `config.json` 的 interval 时，`sync_configured()` 为 true 但 `sync_config()`
  为 None（`daemon.rs`），轮询线程会每轮 `eprintln` 报「未配置同步」——仅噪音。

---

## 修复提交

- 修复：`crates/lk-core/src/storage.rs`（G2-a/G2-b + 2 回归测试）
- 缓解：`crates/lk-cli/src/main.rs`（G1 try_lock 让路）
- 全量验证：fmt / clippy / `cargo test -p lk-core -p lk-cli` / `e2e_m0.sh` / `e2e_m1.sh` 全绿。
