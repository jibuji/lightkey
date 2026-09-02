# 写入授权门规格（write-gate，M2.97）

- 状态：**已设计定稿**（2026-09-02 write-gate grilling 会话收敛拍板；**待实现**——
  按交付纪律登记 decisions #24 后走 PR CI 门禁落地）
- 关联：[authorization-gate.md](authorization-gate.md)（三层模型 / 审批通道 /
  §10 摘要）· [value-disclosure.md](value-disclosure.md)（读/导出裁决，本规格的
  对称扩展）· [ipc.md](ipc.md)（令牌 = 认证 ≠ 授权）·
  [data-model.md](data-model.md)（规则对象 schema 扩展）· [decisions.md](decisions.md)
  #24（拍板记录）。
- **本文是本项的唯一实现规格**；authorization-gate.md §10 只留摘要并指向这里。

## 1. 问题

三层授权门（默认拒绝 / 规则白名单 / 弹窗审批）约束了注入（M2）与值披露
（M2.9），但**写入完全没门**：

- `crates/lk-daemon/src/router.rs` `strategy_of()`：`M_ITEM_PUT` / `M_ITEM_DELETE`
  缺省 `Inline`；
- `crates/lk-daemon/src/daemon/mod.rs` `dispatch()`：`M_ITEM_PUT` /
  `M_ITEM_DELETE` 只过 `require_session`（令牌校验）即执行；
- `crates/lk-daemon/src/daemon/items.rs`：`item_put` / `item_delete` 直接落库
  （CAS / 软删墓碑）。

结果：解锁窗口内任何同用户进程持 `session.token` 跑 `lk item add/edit/delete`
就能**静默**新建 / 整条替换 / 删除任意条目——规则与弹窗完全不参与。这与
value-disclosure.md §1 描述的值披露漏洞**同源**（补充拍板 #20 的镜像面）。
补充拍板 #24 据此把**写入**纳入授权门：**写 = 授权事件**——写规则命中或
弹窗批准才放行；desktop 直调受信豁免、headless fail-closed。

## 2. 目标与非目标

**目标**

1. `item.put`（create / update）与 `item.delete` 从「持令牌即写」升为裁决
   方法：写规则命中 → 静默放行；未命中 → 桌面弹窗批准；否则拒绝。
2. 写规则：新规则能力 `write`（capability=write）+ `actions` 子集，随库加密
   同步，覆盖 git hook / cron / 构建脚本等合法程序化写。
3. **delete 恒弹窗**：任何写规则不豁免（无用户级恢复路径——软删墓碑仅服务
   同步收敛，30 天后硬删，无 restore 命令；对齐 export 恒弹窗的破坏性对称
   先例）。
4. 每次裁决写审计（含拒绝与超时），可事后归因。

**非目标（默认值已定，见 §12）**

- 同步应用阶段（BYO 存储变更落库）不受写门——与值披露同口径，信任模型不变；
- 锁态写一体化（#67/#23 同款「主密码 + 写入」一次交互）：默认不做；
- secret 类型 update 恒弹窗：默认不做（真相源投毒接受为已知限制，§9）；
- 写规则 id 键（对象级钉死）：默认不用（keys 以名称为键，§4）；
- 同用户原生攻击（调试器 / 内存注入 / 键盘钩子等绕过产品接口的路径）仍在
  边界外，如实声明（#15 前半、#17、#18、#20 不变）。

## 3. 判定矩阵

| 通道 | 方法 | 写规则（§4 双向名约束） | GUI 在场 | 结果 |
|------|------|------------------------|----------|------|
| desktop（内嵌直调） | put / delete | 不查 | — | 放行（受信豁免） |
| cli / wsl-bridge（socket，持有效令牌） | `item.put`（create） | 草稿名 ∈ keys | — | 静默放行 + 审计 |
| cli / wsl-bridge | `item.put`（update） | 存储名 ∈ keys **且** 草稿名 ∈ keys | — | 静默放行 + 审计 |
| cli / wsl-bridge | `item.put` | 未命中 | 是 | 弹窗 → allow 放行 / deny·timeout 拒绝 |
| cli / wsl-bridge | `item.put` | 未命中 | 否 | 拒绝 `authz.denied` |
| cli / wsl-bridge | `item.delete` | **恒弹窗，任何规则不豁免** | 是 | 弹窗 → allow 放行 / deny·timeout 拒绝 |
| cli / wsl-bridge | `item.delete` | — | 否 | 拒绝 `authz.denied` |
| 任意 socket（**锁定态**） | put / delete | —（锁态不能预载规则） | 是/否 | fail-closed `session.invalid`（不弹窗；规则在加密库内） |

- 启动者未知 / cwd 不可得（socket 通道）→ 第 1 层 fail-closed 拒绝，不弹窗、
  不留内容（与 inject / 披露同口径）。
- 未初始化库锁态同 `session.invalid`（空库无从解锁）。
- 锁态写一体化（unlock+allow 一次交互）为留档项（§12），本规格**不实现**。

## 4. 写规则（schema 扩展）

`crates/lk-core/src/model.rs` 的 `Rule` 增加一个字段：

```rust
pub struct Rule {
    pub id: Uuid,
    pub project_dir: String,
    pub name: String,
    /// capability=inject 时为具名命令（可 glob）；capability=read/write 时为空串。
    pub command: String,
    pub keys: Vec<String>,
    /// 规则能力类型：inject（注入，默认）| read（读值）| write（写入，M2.97）。
    /// serde(default = "inject") —— 既有规则密文反序列化不受影响。
    pub capability: String,
    /// write 能力下的写动作子集；serde(default) = ["create","update"]。
    /// delete 恒弹窗由协议保证——**不存在于 actions**，规则写不进去。
    pub actions: Vec<String>,
    pub created: String,
}
```

- **兼容性**：`actions` 带 `#[serde(default)]`，`capability != write` 时忽略；
  已密封旧规则解析为 `inject`，无迁移。
- **匹配语义**：
  - **create**（新建）：`capability == "write"` 且 actions 含 `create`，且
    `keys` **精确包含草稿名**（`ItemDraft` 四类型均携带 name）；
  - **update**（整条替换）:actions 含 `update`，且 `keys` **同时包含存储名
    与草稿名**——改名不得「进出」授权名集合：只按结果名匹配会让攻击者把
    非授权条目改名进/出授权集合（改名逃生 / 改名植毒），双向约束闭合；
  - **delete**：**不参与规则匹配**（恒弹窗，§3）；
  - 重名语义：**名字即身份**——规则覆盖全部同名条目（与读规则同构，规格
    明示；`data-model.md` 无名称唯一约束，重名允许）。
- **能力不互授**：`write` 规则不授权读/注入，`read` / `inject` 规则不授权写
  （与 value-disclosure §4 语义一致，扩展到三能力两两不互授）。

## 5. 执行计划与 RPC

### 5.1 策略表

`crates/lk-daemon/src/router.rs` `strategy_of()`：

- `M_ITEM_PUT` / `M_ITEM_DELETE` → `ExecutionStrategy::ApprovalDeferred`；
- `M_ITEM_LIST` 维持 `Inline`（元数据令牌门，不裁决）。

### 5.2 RPC 不拆（拍板，勿改）

**不拆 `item.create` / `item.update`**：拆除 `M_ITEM_PUT` 是**破坏性协议变更**
（旧 daemon / 旧桌面端不兼容，需升桥协议版本或留废弃别名）+ 三处契约镜像
（Rust `ipc.rs` ↔ TS `protocol.ts` ↔ `protocolContract.test.ts`）同步改 +
CLI/daemon/审计/测试表面翻倍。保留单 `M_ITEM_PUT`：

- action 由 daemon 从 `ItemPutParams.id: Option<Uuid>` **权威派生**（None =
  create，Some = update；更新必带 `expected_revision`，CAS 强制）——与
  「不信客户端自报」第一原则一致；
- daemon 内部处理函数拆分 `item_create_exec` / `item_update_exec`（实现面
  拿清晰度，不动协议）；
- `item.delete` 维持独立方法。

### 5.3 begin（命令锁内，非阻塞）

1. `require_session`（令牌校验，现状）；
2. 解析目标条目名：create = `draft.name`；update = id → 存储名 + `draft.name`
   （不存在 → `item.not_found`，现状）；delete = id → 存储名；
3. **通道判定**：`CallerId.channel == Desktop` → 直接放行执行（受信豁免，
   不登记审批）；
4. socket 通道：取真实 starter + cwd（#66 归因链路复用）；未知 → 第 1 层
   拒绝（`authz.denied`，不弹窗）；
5. 写规则匹配（§4）：命中 → 放行 + 审计；delete **跳过规则匹配**，直接
   `open`（恒弹窗）；
6. 未命中：`ApprovalChannel::available()` false（GUI 不在场）→ 立即拒绝
   `authz.denied`；否则登记 `PendingApprovals`（challenge 防伪 #78）+ 广播
   `authz.request`；
7. `ApprovalRequest` 填充：kind = `Write`；command = `"item.put <name>"` /
   `"item.delete <name>"`（展示用）；keys = 单元素 [目标条目名]；
   project_dir = cwd（canonical / wsl:// 规范形）；`needs_unlock = false`。

**锁定态**：begin 前写门预检（对齐 `rule_precheck`：vault 解锁态 + 会话有效
  才继续；锁定 → `session.invalid` 先行，不弹窗）。

### 5.4 finalize（命令锁外等待后，重取命令锁）

- `await_decision`（30s 超时默认拒绝，复用 `PendingApprovals`）；
- allow → **TOCTOU 锁内重校验**（等待窗内可能被并发审批落盘 / 同步轮次
  改变）：
  - vault 仍解锁（锁定 → `session.invalid`，K_audit 已擦除无法签名审计，
    与披露/规则门 finalize 同口径）；
  - delete：目标条目仍存在（按**未删除**口径重验——`read_item_file` 含
    墓碑、幂等 delete 会静默成功，不能用作重验；与规则门 remove 的
    `get_rule` 教训同款）；
- 通过 → 执行 `me.put` / `me.delete`（put 的 CAS 冲突照旧 `item.conflict`）
  + 审计（channel=approval）；deny / timeout / 重验失效 → `authz.denied`
  + 审计。

### 5.5 错误码

复用 `-32017 authz.denied`（协议零新增；-32014~-32016 已被 bridge 占用，
既有实证：规则门与值披露同码复用）。CLI 按命令语境渲染文案（「写入被
授权门拒绝（需桌面审批…）」等），`--json` 机器契约 error 名不变。

### 5.6 不改的部分

- `ItemPutParams` / `ItemDeleteParams` / `ItemDraft` 结构零变更；
- `item.list` / `rule.*` / `vault.*` / `sync.*` / `audit.*` 策略不变；
- 桌面直调豁免语义不变（写入通道加入豁免面，CONTEXT.md「受信豁免」词条
  已同步）；
- 锁定态 headless / 未初始化库 fail-closed 语义不变。

## 6. 审批帧与前端

- `ApprovalKind` 新增 `Write`（serde `"write"`，加性变更不升协议版本）；
  单一 kind + `command` 字段承载动作（`item.put <name>` / `item.delete <name>`）；
  `keys` = 单元素 [目标条目名]；`export_meta` 恒 None。
- 前端 approval 插件 kind=write 分支：动作（create/update/delete）+ 目标
  条目名 + projectDir + 30s 倒计时，**不展示值**；
- **「允许并为此项目记住」仅 create/update 提供**（生成写规则
  `keys=[条目名] + actions=[当前动作]` 的最小授权）；**delete 无记住按钮**
  （恒弹窗语义，任何规则不豁免——对齐 export）；
- 规则管理页与审计页：规则列表展示 capability + actions；审计事件按 §8
  落表。

## 7. CLI

- `lk rule add` 支持写规则形态（**实现注记**：与 `--read` 同款，`--write` 省略
  `<command>` 位置参数，keys 经 `--keys <name...>` 选项给出，防位置参数吞词）：
  ```
  lk rule add <projectDir> --write [--actions create,update] --name <规则名> --keys <条目名...>
  ```
  `--actions` 缺省 `create,update`；传 `delete` 被拒绝（协议恒弹窗，规则不
  该也写不进去）；`rule.list` 展示 capability + actions。
- `lk item add / edit / delete`：收到 `authz.denied` 时提示「写入被授权门拒绝
  （无规则且未批准/超时/无 UI）；可用 `lk rule add <projectDir> --write` 为
  该项目目录预授权」，退出码非零；`--json` 机器契约复用 §5.5。
- 其余命令形态不变。

## 8. 审计

复用 `EventInput`（`crates/lk-daemon/src/daemon/mod.rs`）：

| 字段 | 值 |
|------|-----|
| command | `item.create <name>` / `item.update <name>` / `item.delete <name>`（daemon 侧按 action 派生；值不明文——沿用 `item.put <kind> <redacted>` 脱敏口径） |
| target | 条目名（daemon 侧解析） |
| starter / channel | 调用方归因（#66 真实链路；WSL 侧 `wsl-bridge`） |
| result | allowed（规则命中 / 弹窗批准 / desktop 豁免）/ denied（拒绝、超时、无 UI、fail-closed） |

- 弹窗批准路径由 finalize 审计（channel=approval，与 inject/披露同口径，
  不重复记）；`approval.result` 失败提交审计沿用 #78 现状；
- **全路径审计**（对齐补充拍板 #22 规则门）：unknown starter / no_ui / denied
  / timeout 失败路径均落审计（K_audit 可用时）。

## 9. 边界与已知限制

- **同步应用不受门**：`sync/engine` 把 BYO 存储拉下来的远端变更直接落库
  （应用阶段短写锁内），不经 IPC——写门只覆盖请求面（socket/pipe/CLI/桥/
  桌面直调），与值披露同口径（BYO 存储被可信设备持有，信任模型不变）。
- **真相源投毒（已知限制，接受）**：写规则允许静默改写 secret 类条目值 →
  后续**合法**读规则 / 注入会拿到被污染的值（投毒而非泄密）。缓解：
  delete 恒弹窗已压住最坏损失（不能静默拆墙）；全路径审计可追溯；
  secret 类型 update 恒弹窗为后续可选收紧（§12）。
- **身份边界如声明**：写规则同注入/读规则，授权的是「目录 + 条目名」形态，
  不绑定程序可执行文件身份（authorization-gate.md §3）；同用户进程在
  授权目录内复现即可命中。exe+哈希绑定为整体可选加固（不随本规格）。
- 同用户原生攻击（绕过产品接口）在防护边界外（#15/#20 声明不变）。

## 10. 测试计划（TDD，先红后绿）

1. 单元（lk-core）：
   - `Rule.actions` 序列化往返 + 缺省 `["create","update"]`；旧 JSON →
     inject 且 actions 忽略；
   - 写规则匹配矩阵：create 草稿名命中 / update 双向（存储名 ∧ 草稿名）/
     改名逃生（存储名不在 keys → 不命中）/ 改名植毒（草稿名不在 keys →
     不命中）/ 重名全盖 / 跨命名空间 `wsl://` 归一化两侧一致 / 能力不互授
     （write 不授权 read/inject，反之亦然）；delete 不参与匹配；
   - `ApprovalKind::Write` serde（`"write"`）。
2. 集成（lk-daemon，`tests/write_gate.rs`，先红）：
   - `strategy_of(M_ITEM_PUT / M_ITEM_DELETE)` → `ApprovalDeferred`；
   - desktop 直调 put/delete → 直返，不登记审批；
   - socket + 写规则命中 → 静默放行 + 审计 allowed（create / update 两形态）；
   - socket 无规则 + 有桌面订阅 → allow / deny / timeout 三态 + 审计；
   - socket 无规则 + 无桌面订阅 → `authz.denied` + 审计；
   - **delete 恒弹窗**：即使规则 actions 含 delete（防御性）也弹窗；无 UI →
     拒绝；
   - starter 未知 → fail-closed 拒绝且不弹窗；
   - 锁态 → `session.invalid`（回归）；
   - TOCTOU：等待期锁定 → session.invalid；等待期 delete 目标消失 → 拒绝；
   - socket 提交 `approval.result` → `channel.forbidden`（#78 回归）。
3. E2E（脚本扩展，headless）：无规则 `item.put` → `authz.denied` 非零退出 +
   审计；`rule add --write`（经 `LIGHTKEY_E2E_AUTO_APPROVE=rule` 预插，
   **不扩展 auto-approve 到写门**）后再 put → 静默放行；`item.delete` →
   headless 无 UI 恒弹窗拒绝；审计含 `item.update/delete` 事件。
4. 前端（vitest）：kind=write 弹窗渲染（动作/条目名/倒计时）、记住按钮仅
   create/update、delete 无记住按钮、未知 kind 防御渲染。

## 11. 交付切分

建议 PR 序列（各自出口全绿，走 PR CI 门禁）：

1. **PR A（lk-core）**：`Rule.actions` + 写规则匹配（§4）+ `ApprovalKind::Write`
   + 单测（§10.1）；
2. **PR B（lk-daemon）**：策略表 + begin/finalize 编排（§5）+ 内部
   create/update exec 拆分 + 审计 + 集成测试（§10.2）；
3. **PR C（lk-cli + E2E）**：`rule add --write`、写拒绝文案、脚本扩展（§10.3）；
4. **PR D（前端 + 收尾）**：弹窗 kind=write + 记住按钮 + vitest + 文档收尾
   （authorization-gate §10 状态翻转「已实现」、ipc/cli/agent-cli/data-model/
   milestones、decisions #24 状态翻转、**issue 立项关闭**）。

## 12. 开放问题（默认值已定，改动需重新拍板）

- **锁态写一体化**：默认不做（`session.invalid` 先行）；#67/#23 同款
  「主密码 + 写入」一次交互列为后续可选。
- **secret 类型 update 恒弹窗**：默认不做（真相源投毒接受为已知限制，§9）；
  规则级 flag 后续可选（届时为加性字段，非协议变更）。
- **写规则 id 键**：默认不用（keys 以名称为键，名字即身份）；「只授权这一个
  对象」需求出现时再议（create 无 id 需另案）。
- **弹窗合并去重 + 每 starter 并发上限**：沿用 value-disclosure §12 / #23
  已知限制留档，不阻塞本规格。
- **规则绑定 exe+哈希**：授权的是「目录 + 条目名」形态（§9），进程身份绑定
  属整体可选加固，不随本规格。