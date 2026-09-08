# 架构深化：授权门管线收敛 + 假设缝移除（唯一出处）

- 状态：已拍板（2026-09-07 grilling；船长确认「先落盘 + 先评审」，实施后置）；已过
  2026-09-07 对抗评审修订（§8）、2026-09-08 第三轮对抗评审修订（§10）。
- 来源：`/improve-codebase-architecture` 评审（锁定热点 #146–#160，全在 `crates/lk-daemon` 授权门链路）
- 关联：决策见 [decisions.md](decisions.md) #28；词汇见 [../CONTEXT.md](../CONTEXT.md)
  （新增「对端身份 / 审批注册表 / 门声明」三词条）；ADR-0001 延伸（consequence 注记）。
- 设计词汇：模块 / 接口 / 实现 / 深度 / 缝 / 适配器 / 杠杆 / 局部性 / 删除测试。

## 0. 一句话结论

四处摩擦，四项**行为保持**的深化，按 2 → 3 → 1 → 4 顺序实施；每步 `cargo test`
+ `cargo clippy --all-targets -- -D warnings` 绿再进下一步。**不改变任何审批语义**。

> 「行为保持」的唯一例外（第三轮评审脚注）：候选 3 把 rependable 契约违例从
> 「release 循环内建、超时兜底」改为 release 立即 fail-closed——按构造不可达的
> 防御路径硬化，裁决结果不变（§3）。

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
8. **对端观测不变量**（第三轮评审补）：starter 与 cwd 一律取守护进程侧从 IPC
   对端观测的真实值（`resolve_starter(peer.pid)` / `peer.cwd`，daemon/authz.rs:36-42
   钉的口径），客户端自报字段不信任、仅作提示；跨命名空间归一化
   （`path_ns::canonical_project_dir`，`wsl://` 规范形）不变。候选 4 重排的
   正是这条推导链，重构后必须原样成立。
9. **E2E 面**（第三轮评审补）：候选 2 动 await/resolve 时序 → PR A 验收跑
   `bash scripts/e2e_m2.sh`（审批超时 / 一体化解锁路径）；候选 4 动
   canonical_cwd → 其 PR 验收跑 `bash scripts/e2e_cross_subsystem.sh`
   （无 WSL 前置 SKIP 语义照旧）；同步面未动，`e2e_m1.sh` 不新增要求。

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
- **迁移面（第三轮评审补）**：UI 在场判定 `available()`（现住 core
  `LocalApprovalChannel` 的 `has_ui` 闭包 = PushHub 桌面订阅计数）与
  `authz.request` 广播（现 `open()` 内 `bus.emit`）随注册表一并折入 daemon——
  `AuthzGate` 剥掉通道字段后，四门 begin 的 `available()` 检查**在 PR A 里**就要
  换 daemon 侧谓词，不是留到候选 3。
- **文档面（第三轮评审补）**：`ApprovalChannel` 是 **D8 拍板内容**（spec 出处
  `authorization-gate.md` §6「审批通道抽象（D8）」整节，另有 L289/L322/L337 三处
  局部引用）——删除须同步：① §6 重写为 daemon 侧审批注册表语义；② decisions.md
  **D8 加 #28 修订注记**（同候选 1 对 D16 的处理法）；③ 引用清点 7 份文档
  （authorization-gate / ipc / write-gate / value-disclosure / milestones /
  cross-subsystem / decisions），**规格性描述**逐份改写失实措辞，**历史记录**
  （milestones 里程碑条目、decisions D 行）只加 #28 指针不改写。
- **测试**：行为保持；随代码迁移 + 新增「三拍生命周期」测试（登记 → 裁决写 →
  finalize 单点消费；覆盖超时 / challenge 不符 / workspace 一次性）+ **一条迟到审批
  交错测试**（await 已返 Timeout、finalize 未跑之间插入 `approval.result`，断言
  `accepted=false` + 失败提交审计）；PR A 验收跑 `bash scripts/e2e_m2.sh`（§1.9）。

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
- **文档反转**（第三轮评审修订枚举与判据）：`plugin-architecture.md` 的精确措辞
  「trait 服务」共 **4 处**——§1.1 落地层表（L18）/ §2 术语表（L41）/ §4.1 标题
  （L98）/ §8.2（L337）；另有**变体 3 处**须一并清点：§5.1（L167）「（trait 事件 +
  分发器）」、§5.4（L212）「Rust 侧 trait 实现切换」、plugin-architecture 自身的
  §10 一致性表（L374）「审批通道抽象对应 trait」（该条随候选 2 删 trait 同步
  失修）。修订为「A/B 层 = 具体类型 + 事件总线；保留的 trait 按**三类**」——
  **勿用「≥2 适配器」作判据**（名单 8 trait 中仅 2 个有 ≥2 生产实现，照抄会埋下
  自相矛盾的判据）：① 多生产实现真缝：`StorageBackend`（local/WebDAV/S3）、
  `ProcessTable`（procfs/sysctl/toolhelp）；② 平台抽象 + 白盒测试缝（生产单实现 +
  测试替身）：`VaultRead`、`RuleVault`、`PeerEnv`、`FingerprintSource`；
  ③ 观察者契约：`EventSink`（`ApprovalChannel` 不在保留列——候选 2 整体删除）。
  §4.1 注入图按现实重画；`architecture.md` §3 边界纪律同步；**并修订
  `decisions.md` D16**（2026-08-15 拍板集「trait 服务 + 事件总线」→「具体类型 +
  事件总线」）。

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
    代码**（`resolve_starter(0)` → `UNKNOWN_STARTER`，第 1 层必拒）。删除时**同步
    修正 daemon/authz.rs:184 自称「§3：pid=0 → 不查指纹」的注释**——identity-binding
    §3 判定矩阵的 desktop 行指读/写门**整门豁免**（disclosure.rs:175 等），矩阵
    本身无需动；顺带审视 authz.rs:204 `peer.cwd None → fallback req.cwd`（同意义
    上的兜底死代码——peer.cwd 缺失时 begin 已 NoCwd 拒）。
  - 删 core `fingerprint_matches` 会推翻 identity-binding.md §10.1/§11「比对序纯函数 +
    测试归 lk-core」的归属——**须同步改该文档，或走 needs-decision（二选一，实现前
    定）**。`CallerId` 归因由同一身份解析产出，删门内 inline 重推。

## 6. 涉及文件速览

（第三轮评审修正路径：门模块在 `lk-daemon/src/daemon/` 子目录，`router.rs` 与
identity 三拆在 `lk-daemon/src/` 顶层。）

| 候选 | 文件 |
|------|------|
| 2 | `lk-core/src/authz.rs`、`lk-daemon/src/router.rs`、`lk-daemon/src/daemon/{gate_kit,session,rules,authz,disclosure,write,mod}.rs`、`lk-daemon/src/tests/*`、`docs/authorization-gate.md`（§6 重写）+ D8 注记 + 引用清点 |
| 3 | `lk-daemon/src/router.rs`、`lk-daemon/src/daemon/{gate_kit,authz,disclosure,write,rules}.rs` + tests |
| 1 | `lk-core/src/service.rs`、`lk-daemon/src/daemon/{mod,vault_cmds}.rs`、`docs/{plugin-architecture,architecture}.md`、`decisions.md`（D16/#28） |
| 4 | `lk-daemon/src/{identity(新),peer_env,exe_resolve,binding}.rs`、`lk-daemon/src/daemon/{mod,authz,disclosure,write,rules}.rs`、`lk-core/src/fingerprint.rs`、`docs/identity-binding.md`（§10.1/§11 归属）+ tests |

## 7. PR 序列建议

- PR A：候选 2（审批注册表合一，含 §2 迁移面 `available()`/广播折入与文档面
  authorization-gate §6 重写、D8 注记、引用清点）+ 生命周期测试 + 迟到审批测试 +
  `e2e_m2.sh` 验收 —— 自包含、可独立合。
- PR B：候选 3（裁决骨架收敛，按 §3 分层裁决结果）—— 依赖 A 的单表注册点。
- PR C：候选 1（service.rs 删除 + 文档反转）+ 候选 4（对端身份面）—— 两者互不
  依赖，可拆两 PR 并行或合一串行，均不与 A/B 的注册点冲突；候选 4 与
  identity-binding §10.1/§11 的归属需先定，验收含 `e2e_cross_subsystem.sh`。
  候选 1 与 A/B 无文件冲突、依赖最少，如需先减代码量可提前（顺序非依赖强制）。

每 PR 先按 testing.md 三级策略验红，再改，绿后开 PR 走 GitHub CI 门禁。
文档类修订（spec / decisions / CONTEXT）随所属候选同 PR 落、单独 commit，
不搭车功能提交（a51df74 四词条混入快速保存提交的教训）。

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

## 10. 第三轮对抗评审修订（2026-09-08）

全新 agent 逐条对照代码与 spec 复核本计划（约二十条事实性断言全部核实为真：
六 trait 单 impl、`Box<dyn>` 生产零读、双注册表分裂清理、`resolve` 迟到语义、
8 处 `ApprovalDraft`、rependable/unlock_supported 仅 `debug_assert` 消费、
`fingerprint_matches` 零生产调用、三处 desktop 豁免行号、auto-approve 接线）。
四处结构修正已折入正文，实现以正文为准：

1. **候选 2 文档面（本轮最高分量）**：`ApprovalChannel` 是 D8 拍板内容（spec
   出处 authorization-gate.md §6 整节），原计划删除零文档配套——补 §6 重写 +
   D8 注记（同 D16 处理法）+ 7 份引用文档清点（§2 文档面，历史记录只加指针
   不改写）；PR A 迁移面补 `available()` UI 在场判定与 `authz.request` 广播
   折入 daemon（§2 迁移面）。
2. **候选 1 真缝判据**：「≥2 适配器」对名单 8 trait 中 6 个不成立（仅
   StorageBackend/ProcessTable 有 ≥2 生产实现，其余为 1 生产 + 测试替身），
   改为三类分法（§4）；「5 处」枚举修正为精确 4 处 + 变体 3 处（含
   plugin-architecture §10 一致性表随候选 2 失修项）。
3. **回归边界补钉**：对端观测不变量（starter/cwd 不信客户端自报）入 §1.8；
   `e2e_m2.sh`（候选 2）与 `e2e_cross_subsystem.sh`（候选 4）入验收（§1.9/§7）。
4. **记录修正**：§6 文件表路径改为 `daemon/` 子目录实况；候选 4 死代码删除补
   注释修正与 authz.rs:204 兜底审视（§5）；§0 补「行为保持」例外脚注（rependable
   release fail-closed 防御硬化）；decisions.md #28 同步（真缝判据三类、候选 2
   直接删 + D8 文档面、落点四词条）；CONTEXT.md 门声明「七步」改「六步」。