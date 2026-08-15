# G1 根治重构 review 报告（PR #11）

- 审查对象：PR #11 `fm/lightkey-m1-lock-rework`（head `7c12da5`），
  相对 `origin/main` 的 diff（9 文件 +1266/−325）。
- 审查范围：船长原则（权限/锁语义分层）、并发正确性、M0/M1 不回归、测试真实性。
- 结论：**发现 1 个中等级正确性缺陷 + 2 个低等级一致性问题，全部当场修复**
  并追加回归测试；全量验证通过（fmt / clippy / test / e2e_m0 / e2e_m1）。

## 验证结果

| 检查 | 结果 |
|------|------|
| `cargo fmt --all -- --check` | ✅ 通过 |
| `cargo clippy -p lk-core -p lk-cli --all-targets -- -D warnings` | ✅ 通过 |
| `cargo test -p lk-core -p lk-cli` | ✅ 通过（lk-core 68 / lk-cli 1 守护并发回归 / properties 8 / sync_properties 1） |
| `bash scripts/e2e_m0.sh` | ✅ 41 通过 / 0 失败 |
| `bash scripts/e2e_m1.sh` | ✅ 38 通过 / 0 失败 |
| Windows 交叉 `cargo check --target x86_64-pc-windows-*` | ⚠️ 本机缺 mingw-w64/msvc 工具链（`cc-rs` 找不到编译器），无法本地交叉；改动均不触碰 `cfg(windows)`/`cfg(unix)` 路径，由 CI（Windows）兜底确认 |

## 船长原则核对（结论：落实，无越界）

- **网络 I/O 全程无锁** ✅：`run_sync_round_with` 抓取阶段经 `LockedVaultView`
  每次调用独立短读锁（仅本地内存/磁盘），网络调用发生在各方法之间，不持任何锁。
- **命令与后台同步并发** ✅：轮询线程与 `sync.trigger`（`try_sync_trigger`）均在
  命令互斥锁外执行轮次；`item.list` 在慢网络窗口内及时返回（守护并发回归测试实证）。
- **锁只做内存一致性** ✅：vault 用 `RwLock`（命令读写、同步仅应用阶段短写）；
  权限语义（unlock/session/令牌/锁定/退出/恢复）完全不变。
- **数据冲突交 CAS + last-write-wins** ✅：推送快照守卫 + 应用阶段 LWW 复核 + CAS 兜底。

## Findings

### S1（中）索引 CAS 重试间旧拉取缓冲可回写覆盖远端更新版本 —— 已修复

- 位置：`crates/lk-core/src/sync.rs` `fetch_round`（约 L426–L450）、`merge_indexes`。
- 问题：`pulled: HashSet<Uuid>` 仅按 id 去重。当本轮索引 CAS 冲突触发有界重试、
  且重试间他端把某条目推进到更新 revision 时，重试循环对已 pull 的 id 直接
  `continue`，导致 `plan.imports` 里残留**旧 revision 的缓冲**；随后
  `merge_indexes` 以 `pending`（旧缓冲）为底回写索引，把远端索引**回退到旧
  revision**，而远端密文已是新版本 —— 违反模块文档宣称的
  「远端索引引用的密文恒与索引条目一致」不变量，造成索引/密文不一致与反复摇摆
  （最终仍收敛，无数据丢失，但产生额外拉锯）。
- 修复：`pulled` 改为 `HashMap<Uuid, String>`（id → 缓冲时的远端 revision），
  仅当远端 revision 未前进才跳过；前进则重新拉取。并新增
  `SyncPlan::upsert_import`（L279–L287）按 id 替换旧缓冲，避免同 id 在
  `imports` 中残留过期/重复条目。
- 回归测试：`index_cas_retry_does_not_regress_remote_revision`
  （`sync.rs` L1975），用注入后端在首次索引 CAS 写时模拟并发客户端推进条目
  revision + 重写索引。**已实证：去掉修复后该测试失败（本地采纳到 "A-v2" 旧版本，
  断言 "C-v4" 失败），修复后通过。**

### S2（低）CAS 重试间 `plan.imports` 出现同 id 重复/过期条目 —— 已修复

- 位置：`crates/lk-core/src/sync.rs` `pull_entry`（L586）与 `push_entry` 采纳路径（L730）。
- 问题：与 S1 同根——重试间同一条目可被再次缓冲，`plan.imports` 累积重复项，
  应用阶段虽因 LWW 复核而最终正确，但 `summary.pulled` 可能重复计数、产生冗余写。
- 修复：两处 `plan.imports.push(...)` 改为 `plan.upsert_import(...)`，保证每 id
  至多一条且恒为最新缓冲。

### S3（低）`LockedVaultView::tombstones` 在锁定态静默返回空（与其他读取不一致）—— 已修复

- 位置：`crates/lk-cli/src/daemon.rs` L832–L836。
- 问题：`index_snapshot`/`item` 等在锁定态返回 `Err(SessionInvalid)`（本轮放弃），
  但 `tombstones` 返回 `Ok(默认空)`，锁/恢复竞态下会静默跳过墓碑硬删裁决，
  与模块文档「锁定/恢复竞态 → 本轮放弃」语义不一致。
- 修复：改为锁定态返回 `Err(Error::SessionInvalid)`，与其它读取一致，竞态下
  干净放弃本轮（应用阶段另有密钥复核兜底）。

## 观察项（未改，无需动作）

- `Daemon::handle` 的 `M_SYNC_TRIGGER` 分支是「直接 handle() 调用」回退，会在命令
  互斥锁内执行轮次（网络 I/O 期间持命令锁）。生产路径已被 `try_sync_trigger` 拦截，
  该分支不可达（仅测试用），未改。
- 新增守护并发回归测试 `sync_round_does_not_block_commands_and_apply_respects_races`
  确能证明「同步进行中命令不被阻塞」：慢后端每步发信号、测试在窗口内断言
  `item.list` 及时返回且 `item.put` 成功、应用阶段 LWW 复核不覆盖并发更新——测试真实有效。
