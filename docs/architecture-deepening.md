# 架构深化：授权门管线收敛 + 假设缝移除（唯一出处）

- 状态：已拍板（2026-09-07 grilling；船长确认「先落盘 + 先评审」，实施后置）；已过
  2026-09-07 对抗评审修订（§8）。
- 来源：`/improve-codebase-architecture` 评审（锁定热点 #146–#160，全在 `crates/lk-daemon` 授权门链路）
- 关联：决策见 [decisions.md](decisions.md) #28；词汇见 [../CONTEXT.md](../CONTEXT.md)
  （新增「对端身份 / 审批注册表 / 门声明」三词条）；ADR-0001 延伸（consequence 注记）。
- 设计词汇：模块 / 接口 / 实现 / 深度 / 缝 / 适配器 / 杠杆 / 局部性 / 删除测试。

## 0. 一句话结论

四处摩擦，四项**行为保持**的深化，按 2 → 3 → 1 → 4 顺序实施；每步 `cargo test`
+ `cargo clippy --all-targets -- -D warnings` 绿再进下一步。**不改变任何审批语义**。

> **与 #146 的关系**：本计划是 #146「授权门链路架构深化」（2026-09-06 评审，
> 六重构 #147–#152，全部已合并进 v0.1.17）落地后的**第二轮回溯**。#146 六重构
> 解决的是「编排复制 8 处 / 临时解锁靠注释 / 前端推门语义 / 进程探查跨文件」；
> 本计划四候选是它们落地后**仍残留**的摩擦（双注册表、begin 骨架四份、service.rs
> 假设缝、identity 三拆后缺复合接口）。候选编号为本计划自用，与 #146 内部编号
> 及 #146 Out of Scope 停放的四项（候选 3 AuthzGate 统一求值 / 候选 6 CLI / 候选 7
> tauriAdapter / 候选 8 desktop→PeerOrigin）**不是同一编号**；本计划候选 3 ≈ #146
> 「AuthzGate 统一求值（未选，编排收敛落地后可重新评估）」的续评。

## 1. 回归边界（安全不变量，重构不可触碰）

1. CLI/socket 请求的数据读取 / 写入 / 注入**必过三层授权门**（默认拒绝 → 规则白名单 → 弹窗审批），
   除非完全命中库内规则（第 2 层静默放行）。
2. 无自动审批——唯一的自动路径是第 2 层规则命中；E2E `LIGHTKEY_E2E_AUTO_APPROVE=rule`
   只对规则门 add/remove（**永不碰 inject/读值/写入**），环境变量门控、启动横幅、
   审计 `channel=auto-approve` 全部原样（#22 不动）。
3. 规则增删本身是授权事件（对称原则 #22）——CLI 发起必须 GUI 弹窗批准，headless
   fail-closed；GUI 自身走 desktop 受信豁免。
4. `item.export` 与 `item.delete` **恒弹窗**（任何规则不豁免；desktop 直调豁免照旧）。
5. 元数据 `item.list` / `rule.list` 只过令牌门（认证），不进门——「值是边界」不变。
6. 每个方法的 fail-closed 响应码（inject 的 `ok{allowed,reason}`/`session.invalid` vs
   其余的错误码 `authz.denied`(-32017)/`session.invalid`）是 spec 钉死的，逐门保留。
7. 回归钉沿用 #146 Testing Decisions：五组门集成测试（注入裁决 / 值披露 / 规则门 /
   写门 / 指纹绑定）原样全绿；无痕断言、密码错重试、等待期竞争断言不弱化；
   CLI 面零变化（CLI 契约测试是免费证据）；E2E auto-approve 不扩（#22）。

## 2. 候选 2 · 审批注册表合一（先做）

- **问题**：一次审批被登记进跨 core/daemon 的**两张图**——core `PendingApprovals`
  （challenge/decision/expires + condvar await）与 daemon `PendingGates`
  （`GateEntry{needs_unlock,workspace,kind}`），同一 request_id；`needs_unlock` 存两份；
  清理劈成两半（超时删 core 条目、daemon 条目滞留到 finalize）；`store_workspace`
  因此要兜超时竞态。
- **做法**：单表安 daemon（「审批注册表」，key = request_id），条目承载 challenge/
  expires/decision + needs_unlock/workspace/kind。core `PendingApprovals`（含 await/
  resolve/condvar）随之下沉 daemon。`finalize` 是唯一消费移除点；`await_decision`
  只读不移除。**`resolve` 保留过期/未知拒绝写**（条目过期或 unknown requestId → 不写
  decision、return false → 桌面 `accepted=false` + 写一条「失败提交 Denied」审计，
  与现 `session.rs:59-69` 语义一致）；challenge 校验（#78 防伪回传 DoS：挑战不符
  **不移除**条目）原样保留。unlock 路径在同一临界区先 `store_workspace` 再 `resolve`
  ——**不产生错误结果**；但白费临时解锁 + `vault.unlock` 审计在超时竞态下仍会发生
  （解锁发生在临界区之前，与现行为等价，非本次消除目标）。
- **清理**：删除 `ApprovalChannel`/`LocalApprovalChannel`/`AutoApproveChannel` 三件与
  其 remote 语义占位（`await_decision` trait 方法 + `open` 的 `expires_at` 预留均生产
  零派发）；`AuthzGate` 剥掉 `Arc<dyn ApprovalChannel>` 字段；E2E rule 自动批准折入
  daemon（`rule_auto` 启动读一次的布尔；规则门直接写 `decision=Allowed`、不广播，
  `via_auto` → `AuditChannel::AutoApprove` + requestId 后缀的接线必须存活）。
- **测试**：行为保持；随代码迁移 + 新增「三拍生命周期」测试（登记 → 裁决写 →
  finalize 单点消费；覆盖超时 / challenge 不符 / workspace 一次性）+ **一条迟到审批
  交错测试**（await 已返 Timeout、finalize 未跑之间插入 `approval.result`，断言
  `accepted=false` + 失败提交审计）。

## 3. 候选 3 · 裁决骨架收敛（次做）

- **问题**：四个 `*_begin` 重抄同一条六步骨架（解析 → desktop 豁免 → starter/cwd →
  fail-closed → 规则命中 → 登记广播）；fail-closed 次序是安全不变量却靠复制纪律；
  `DeferredFlow` trait + 四个 `*Flow` 壳是纯委托 + 两个只被 `debug_assert!` 读的布尔；
  `ApprovalDraft` ≈ `ApprovalRequest` 九字段克隆在 8 处写 `None`。
- **做法**：「门 = 一份**静态声明**」（precheck/begin/finalize 三个 fn 指针 +
  rependable/unlock_supported 两个布尔 + 本门事实 + 响应渲染器），`router::gate_flow`
  返回它。布尔成为一等数据——编排器 release 下真消费；**契约违例（声明不可 RePended
  却返回 RePended）release 下 fail-closed**（debug 仍断言）。
- **裁决结果须分层**（评审修订，实现以此为准）：`session.invalid` 与 TOCTOU 失效是
  **执行失败**而非 Denied 决策（decision 已 Allowed 而 vault 已锁 / resolve_env 失败 /
  重验失效）；同一 reason（no_ui / unknown_starter）跨门、跨锁态字节不同（锁态
  inject=`session.invalid` vs 解锁态=`ok{no_ui}` vs disclosure=`authz.denied`）。因此：
  - begin 阶段的**裁决结果** = 拒绝(reason) / 放行(负载) / 未命中需审批；
  - finalize 阶段再分「**决策结局**（deny/timeout → 统一拒绝尾）」与「**执行结果**
    （Allowed 后执行成功 / `session.invalid` / TOCTOU 重拒）」两层；
  - 每个渲染器**必须拿 (门 + 锁态/会话态) 上下文**，不能是「决策 → 字节」的纯函数，
    否则 6 类 spec 钉死的 fail-closed 码会被压平。
- **范围**：一次吃掉 begin 骨架 + finalize「denied 尾」收尾 + `ApprovalDraft` 克隆。
  **不进**：In/OutsideLock 策略、参数化响应字节（ADR-0001 否决项）。
- **测试**：补一张「逐门 × 逐状态响应字节」golden 表（钉住 6 类 fail-closed 码，
  注册表完整性测试只钉 rependable/unlock_supported 不够）。

## 4. 候选 1 · 服务层 trait 假设缝（含文档反转）——评审 SOUND，可直接推进

- **问题**：`lk-core/src/service.rs` 六个 A/B trait 服务各一个适配器、方法体皆
  `fn x(){self.x()}` 透传、`dyn` 生产零派发；`CoreServices{crypto:Box<dyn>,recovery:Box<dyn>}`
  两个字段生产从未读，生产只用 `bus/new_session/attach_vault/subscribe`。
- **做法**：删六 trait + 各自唯一 impl + 两 `Box<dyn>` 字段与访问器；具体类型直用；
  `CoreServices` 溶解（daemon 直持 `Arc<EventBus>`；`SessionManager::new().attach_bus`
  与 `vault.attach_bus` 两行直连）。`service.rs` 模块拆清，`bus.rs`/`session.rs`/`vault`/
  `sync`/`audit` 各归其位。`service.rs` 的两个 trait 层测试无对应位置可迁——走**删除
  测试流程**（断言删除后无调用点需要等价物），非「迁移」。
- **文档反转**：`plugin-architecture.md`「Rust 侧 = trait 服务」措辞出现在 §1.1/§2
  术语表/§4.1 标题/§5.4/§8.2 共 5 处（非仅 §3/§4），须逐处修订为「具体类型 +
  事件总线；真缝 trait 仅保留 ≥2 适配器的 StorageBackend / VaultRead / RuleVault /
  ApprovalChannel（候选 2 一并删）/ EventSink / ProcessTable / PeerEnv /
  FingerprintSource」；§4.1 注入图按现实重画；`architecture.md` §3 边界纪律同步；
  **并修订 `decisions.md` D16**（2026-08-15 拍板集「trait 服务 + 事件总线」→
  「具体类型 + 事件总线」）。

## 5. 候选 4 · 对端身份面（后做）

- **问题**：#152 把 `identity.rs` 拆成 `peer_env`/`exe_resolve`/`binding` 三个平铺模块
  （白盒可测），但「谁在调、从哪调」这个复合体无名无接口，每个 `*_begin` 手拼
  `derive_starter + canonical_project_dir`；Deferred 方法绕过 `CallerId::of`，两条归因
  路径并立；core `fingerprint_matches`（§5.2 比对序）零生产调用者、与 binding.rs
  缓存感知版重复。
- **做法**：daemon 新增 `identity` 深模块，唯一接口 `resolve(peer)` →
  **{ starter, canonical_cwd, exe_path }**；门面委托 `starter`(core)/`peer_env`/
  `exe_resolve`/`binding`（三拆保留为内部缝）。**指纹裁决不并入门面**——它是消费
  解析 exe 路径的**单独一步**（需 vault 绑定规则 + `&mut cache`，锁态补裁决在临时
  vault 解锁后，`authz.rs:406-411`），保持为独立调用且不吞 #140 单次裁决 gating。
  - **desktop 豁免键 = `peer.origin == Desktop`**（在 derive_starter 之前，
    disclosure.rs:175 / write.rs:119 / rules.rs:84），`peer.pid == 0` 不是豁免键；
    `fingerprint_adjudicate` 内 `pid == 0 → NotApplicable`（authz.rs:185-187）是**死
    代码**（pid=0 先被 unknown-starter 第 1 层拒绝），照删或标注。
  - 删 core `fingerprint_matches` 会推翻 identity-binding.md §10.1/§11「比对序纯函数 +
    测试归 lk-core」的归属——**须同步改该文档，或走 needs-decision（二选一，实现前
    定）**。`CallerId` 归因由同一身份解析产出，删门内 inline 重推。

## 6. 涉及文件速览

| 候选 | 文件 |
|------|------|
| 2 | `lk-core/src/authz.rs`、`lk-daemon/src/{gate_kit,session,router,mod,rules}.rs`、`src/tests/*`、`router.rs` tests |
| 3 | `lk-daemon/src/{router,gate_kit,authz,disclosure,write,rules}.rs` + tests |
| 1 | `lk-core/src/service.rs`、`lk-daemon/src/{mod,vault_cmds}.rs`、`docs/{plugin-architecture,architecture}.md`、`decisions.md` #28 |
| 4 | `lk-daemon/src/{identity(新),mod,authz,disclosure,write,rules}.rs`、`lk-core/src/fingerprint.rs`、`docs/identity-binding.md`（§10.1/§11 归属）+ tests |

## 7. PR 序列建议

- PR A：候选 2（审批注册表合一）+ 生命周期测试 + 迟到审批测试 —— 自包含、可独立合。
- PR B：候选 3（裁决骨架收敛，按 §3 分层裁决结果)—— 依赖 A 的单表注册点。
- PR C：候选 1（service.rs 删除 + 文档反转）+ 候选 4（对端身份面）—— 可并行或串行，
  均不与 A/B 的注册点冲突；候选 4 与 identity-binding §10.1/§11 的归属需先定。

每 PR 先按 testing.md 三级策略验红，再改，绿后开 PR 走 GitHub CI 门禁。

## 8. 对抗评审修订（2026-09-07）

全新 agent 读本计划 + 逐条对照代码与 spec 后裁定：候选 1 **SOUND**、候选 2 **RISKY**、
候选 3 **FLAWED**（结构）、候选 4 **RISKY**。三处结构修正已折入 §2/§3/§5 正文，实现
以正文为准，本节为修订记录摘要：

1. **候选 2**：明定 `resolve` 保留过期/未知拒绝写（迟到回传 `accepted=false` + 失败
   提交审计不回翻）；「store+resolve 原子化」只保证不产生错误结果，不消除白费解锁
   审计；补迟到审批交错测试。
2. **候选 3**：裁决结果分「拒绝/放行/需审批」与「决策结局 vs 执行结果」两层；渲染器
   带 (门 + 锁态/会话态) 上下文；rependable/unlock_supported release 契约违例 fail-closed；
   补逐门×逐状态响应字节 golden 表。
3. **候选 4**：`对端身份` 只含 {starter, canonical_cwd, exe_path}，指纹裁决为单独一步；
   desktop 豁免键在 `peer.origin`；`pid==0` 分支是死代码；删 core `fingerprint_matches`
   需同步改 identity-binding §10.1/§11 或 needs-decision。

## 9. 二次评审核实（2026-09-07 第二轮）

第三方（再次以全新 agent）对本计划复核，其中两条**事实性误判**（以仓库现状为准）：
（B4 称 decisions.md 末条为 #26、#28 跳号——实际 #27 快速保存存在，#28 正确；
B6 称工作区有 7 个 #146 收尾文档 diff —— `git status` 无 authorization-gate /
data-model / identity-binding / ipc / milestones / write-gate / AGENTS.md 改动，
仅 quick-capture（#161）前端 + 本计划四文档）。**有效修正已并入 §0/§1/§4**：
① 明示与 #146 的连续关系与候选映射；② 文档反转逐处枚举 + 修订 D16；③ 回归边界
锚定 #146 Testing Decisions；④ 修订 #146「不新增 CONTEXT.md 词条」决策；⑤ ADR-0001
consequence 注记与本计划的注记合并为一条（不并列）。