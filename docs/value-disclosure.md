# 值披露裁决规格（value-disclosure，M2.9）

- 状态：**已实现**（补充拍板 #20；issue #65 主体；M2.9 落地——实现与
  spec 的两处偏差见 §5.4 错误码注记与 §7 CLI 形态注记）
- 关联：[authorization-gate.md](authorization-gate.md) §8（摘要与边界）·
  [ipc.md](ipc.md) §3（令牌 = 认证 ≠ 授权）· [decisions.md](decisions.md)
  补充拍板 #20 · [milestones.md](milestones.md) M2.9
- 本文是本项的**唯一实现规格**；authorization-gate.md §8 只留摘要并指向这里。

## 1. 问题

三层授权门（默认拒绝 / 规则白名单 / 弹窗审批）目前只覆盖 `authz.evaluate`
（唯一调用方 `lk inject`）。值离开守护进程的另一条路完全没门：

- `crates/lk-daemon/src/router.rs` `strategy_of()`：仅 `M_AUTHZ_EVALUATE` 是
  `ApprovalDeferred`，其余缺省 `Inline`；
- `crates/lk-daemon/src/daemon/mod.rs` `dispatch()`：`M_ITEM_GET` /
  `M_ITEM_EXPORT` 只过 `require_session`（令牌校验）即执行；
- `crates/lk-daemon/src/daemon/items.rs`：`item_get` 返回含值的完整条目；
  `item_export` 返回整条目数据包（含附件原始数据，base64）。

结果：解锁窗口内，任何同用户进程持 `session.token`（GUI 解锁即落盘）跑
`lk item get <id>` 就能拿明文，规则与弹窗完全不参与。被提示注入操纵的
agent 走这条路即可绕过整个授权门——而「约束这类 agent」正是 D8 的立项
目标。补充拍板 #20 据此把边界修订为**产品接口面即边界**：令牌只做认证，
值的披露必须是授权事件。

## 2. 目标与非目标

**目标**

1. `item.get` / `item.export` 从「持令牌即返回」升为裁决方法：读规则命中
   → 静默放行；未命中 → 桌面弹窗批准；否则拒绝。
2. 读规则：新规则能力类型（projectDir + keys，无 command 绑定），随库
   加密同步，覆盖 git hook / cron / VSCode task / WSL bridge 等合法程序化读。
3. 桌面 GUI 读值体验零变化（内嵌直调受信豁免，不弹窗）。
4. 每次裁决写审计（含拒绝与超时），可事后归因。

**非目标（默认值已定，见 §12）**

- 元数据（`item.list` 名称、`rule.list` 规则内 key 名）维持令牌门，不做
  strict 隐藏旋钮；
- 锁态 `item.get` 不做 #67 式「解锁 + 授权」一体化，维持 `session.invalid`；
- #68 选项 2（常驻进程持令牌）观望，不与本项捆绑；
- 同用户原生攻击（调试器 / 内存注入 / 键盘钩子等绕过产品接口的路径）
  仍在边界外，如实声明（#15 前半、#17、#18 不变）。

## 3. 判定矩阵

| 通道 | 方法 | 读规则 | GUI 在场 | 结果 |
|------|------|--------|----------|------|
| desktop（内嵌直调） | get / export | 不查 | — | 放行（受信豁免） |
| cli / wsl-bridge（socket，持有效令牌） | `item.get` | 命中 | — | 静默放行 + 审计 |
| cli / wsl-bridge | `item.get` | 未命中 | 是 | 弹窗 → allow 放行 / deny·timeout 拒绝 |
| cli / wsl-bridge | `item.get` | 未命中 | 否 | 拒绝 `authz.denied` |
| cli / wsl-bridge | `item.export` | **永不豁免** | 是 | 弹窗 → allow / deny·timeout |
| cli / wsl-bridge | `item.export` | — | 否 | 拒绝 `authz.denied` |
| 任意 socket | `item.list` / `rule.list` | — | — | 维持现状（令牌门，不裁决） |

- 启动者未知 / cwd 不可得（socket 通道）→ 第 1 层 fail-closed 拒绝，
  不弹窗、不留内容（与 inject 同口径）。
- vault 锁定时 `require_session` 先失败 → `session.invalid`（现状不变）。
- `item.export` 是整条目数据包（含附件原始数据）外带，单次披露量最大，
  所以**恒弹窗**：读规则、inject 规则、任何白名单都不豁免。

## 4. 读规则（schema 扩展）

`crates/lk-core/src/model.rs` 的 `Rule` 增加一个字段：

```rust
pub struct Rule {
    pub id: Uuid,
    pub project_dir: String,
    pub name: String,
    /// capability=inject 时为具名命令（可 glob）；capability=read 时为空串。
    pub command: String,
    pub keys: Vec<String>,
    /// 规则能力类型：inject（注入，默认）| read（读值）。
    /// serde(default = "inject") —— 既有规则密文反序列化不受影响。
    pub capability: String,
    pub created: String,
}
```

- **兼容性**：`capability` 带 `#[serde(default)]`，已密封的旧规则解析为
  `inject`，无迁移；新规则旧客户端读到的多余字段被忽略。
- **匹配语义**（读请求：条目名 = `item.name`，守护进程按 id 解析）：
  - `project_dir` 祖先/通配匹配调用方 cwd（与 inject 规则同一套匹配函数；
    WSL 侧两侧同经 `path_ns::canonical_project_dir` 归一为 `wsl://` 形态）；
  - `capability == "read"` 且 `keys` **精确包含**条目名（不做 key 通配，
    与 inject 的 keys 语义一致）；
  - 命中任一读规则即放行该条目。
- **能力不互授**：`inject` 规则不授权读，`read` 规则不授权注入，
  `export` 无规则路径。
- **写入路径**（沿用 D8 两条合法路径，均写审计）：
  1. CLI：`lk rule add <projectDir> --read --name <name> <keys...>`
     （`--read` 时 command 位置参数省略）；
  2. 桌面规则管理页 + 弹窗「允许并为此项目记住」一键（见 §6）。

## 5. 执行计划与 RPC

### 5.1 策略表

`crates/lk-daemon/src/router.rs` `strategy_of()`：

- `M_ITEM_GET` / `M_ITEM_EXPORT` → `ExecutionStrategy::ApprovalDeferred`
  （复用 #81 的两阶段编排：命令锁内 begin → 锁外等待决策 → finalize）。

### 5.2 begin（命令锁内，非阻塞）

1. `require_session`（令牌校验，现状）；
2. 解析条目：id → 条目名（不存在 → `item.not_found`，现状）；
3. **通道判定**：`CallerId.channel == Desktop` → 直接放行返回值（受信
   豁免，不登记审批）；
4. socket 通道：取真实 starter + cwd（#66 归因链路复用）；未知 → 第 1 层
   拒绝（新错误码，见 5.4）；
5. `item.get`：读规则匹配（§4）→ 命中 → 放行 + 审计；未命中 →
   `ApprovalChannel::open`（GUI 不在场 `available() == false` → 立即拒绝）；
6. `item.export`：跳过规则匹配，直接 `open`；
7. `ApprovalRequest` 填充：starter / project_dir（cwd）/ keys=[条目名] /
   kind（见 §6）/ challenge / `needs_unlock = false`。

### 5.3 finalize（命令锁外）

- `await_decision`（30s 超时默认拒绝，复用 `PendingApprovals`）；
- allow → 返回值 / 数据包 + 审计 allowed；
- deny / timeout / 无 UI → `authz.denied` + 审计；
- 审批回传仍走 `approval.result`（仅 desktop 直调可提交 + challenge
  原样回带，#78 语义零改动，socket 伪造提交照旧 `channel.forbidden`）。

### 5.4 错误码

`crates/lk-core/src/ipc.rs` 新增：

- `ERR_AUTHZ_DENIED: i64 = -32017`，消息 `authz.denied`（读裁决拒绝/超时/
  无 UI，统一不区分原因，防探测）。
  **实现注记**：spec 原定 `-32015`，但 `-32014`～`-32016` 已被 lk-cli
  bridge 错误码占用（`ERR_BRIDGE_NO_DAEMON` / `ERR_BRIDGE_VERSION_INCOMPATIBLE`
  / `ERR_BRIDGE_IO`，M2.75）——撞码会使 `bridge.version_incompatible`
  被 CLI 侧误分类为 `authz.denied`，故取顺次空闲码 `-32017`，语义不变。

### 5.5 不改的部分

- 请求/响应参数结构（`ItemGetParams` / `ItemExportParams` 等）零变更；
- `item.list` / `rule.*` / `vault.*` / 同步方法策略不变；
- 锁态行为不变：锁定 → `session.invalid`（本项不做读通道的解锁一体化，
  理由见 §12）。

## 6. 审批帧与前端

- `crates/lk-core/src/authz.rs` `ApprovalRequest` 增加
  `kind: ApprovalKind`（`Inject | Read | Export`，serde camelCase）；
  `command` 字段填 `"item.get"` / `"item.export"`（展示用），`keys` 为
  单元素 [条目名]。自端封闭实现，无兼容包袱。
- 前端 approval 插件按 kind 渲染：
  - `read`：展示启动者 / 项目目录 / 条目名 / 倒计时（不展示值）；
  - `export`：额外展示数据包规模（name/mime/size）；
  - 均提供「允许本次」/「拒绝」按钮；**「允许并为此项目记住」仅 `read`
    提供**，`export` 不提供（恒弹窗语义）。「允许并为此项目记住」
    = allow 决策 + 追加一条 `rule.add`（channel=desktop，capability=read，
    keys=[条目名]，projectDir=弹窗展示的 cwd）。
- 桌面规则管理页与审计页：规则列表展示 capability；审计事件按 §8 落表。

## 7. CLI

- `lk item get <id>` / `lk item export <id>`：收到 `authz.denied` 时提示
  「读取被授权门拒绝（无规则且未批准/超时）；可用 `lk rule add --read`
  为该项目目录预授权」，退出码非零；
- `lk rule add` 支持 `--read`（§4）；`lk rule list` 展示 capability；
  **实现注记**：clap 位置参数按定义顺序贪婪匹配，`--read` 省略
  `<command>` 时位置 `<keys...>` 的第一个词会被可选 `<command>` 占位吞掉，
  故读规则的 keys 经 `--keys <name...>` 选项给出（与 `lk inject --keys`
  同形态）：`lk rule add <projectDir> --read --name <name> --keys <name...>`；
- 其余命令形态不变。

## 8. 审计

复用 `EventInput`（`crates/lk-daemon/src/daemon/mod.rs`）：

| 字段 | 值 |
|------|-----|
| command | `item.get` / `item.export` |
| target | 条目名（daemon 侧按 id 解析） |
| starter / channel | 调用方归因（#66 真实链路；WSL 侧 `wsl-bridge`） |
| result | allowed（规则命中 / 弹窗批准 / desktop 豁免）/ denied（拒绝、超时、无 UI、fail-closed） |

弹窗批准路径由 finalize 审计（channel=approval 与 inject 同口径，不重复
记）；`approval.result` 失败提交审计沿用 #78 现状。

## 9. WSL / 跨子系统

- WSL 内 `lk item get` 经 bridge：channel=`wsl-bridge`，starter 为 interop
  链（已实证可见），cwd 为 bridge 进程真实 cwd（`wsl://<distro>/…` 规范形）
  ——读规则按同一归一化形态匹配，两侧同函数，无新机制；
- 解锁态跨子系统复用仍是特性（补充拍板 #14/#20），本项只约束值的披露，
  不改 bridge 探测/分型/协议版本校验。

## 10. 测试计划（TDD，先红后绿）

**Seam 约定**（实现前确认）：策略与分发行为测 `router.rs strategy_of` +
daemon 集成测试（既有 daemon 装配）；规则匹配测 lk-core 单元；弹窗测前端
vitest（mock 适配器）。

1. 单元（lk-core）：
   - `Rule` 带 `capability` 序列化往返；旧 JSON（无该字段）→ 解析为 inject；
   - 读规则匹配：cwd 祖先匹配、capability 过滤、keys 精确名、inject 规则
     不授权读、read 规则不授权注入、`wsl://` 归一化两侧一致；
   - `ApprovalKind` 序列化。
2. 集成（lk-daemon，先红）：
   - `strategy_of(M_ITEM_GET / M_ITEM_EXPORT)` → `ApprovalDeferred`；
   - desktop 直调 get/export → 直返值，不登记审批；
   - socket + 读规则命中 → 静默放行 + 审计 allowed；
   - socket 无规则 + 有桌面订阅 → allow/deny/timeout 三态 + 审计；
   - socket 无规则 + 无桌面订阅 → `authz.denied`(-32015) + 审计；
   - export：即使读规则命中也弹窗；无 UI → 拒绝；
   - starter 未知 → fail-closed 拒绝且不弹窗；
   - socket 提交 `approval.result` → `channel.forbidden`（#78 回归）；
   - 锁定态 → `session.invalid`（回归）。
3. E2E（`scripts/e2e_m2.sh` 扩展，headless）：无规则 `lk item get` →
   `authz.denied` 非零退出 + 审计；`lk rule add --read` 后再读 → 静默放行；
   `lk item export` → headless 无 UI 拒绝；审计含 `item.get` 事件。
   （弹窗 allow/deny 路径由集成测试的假桌面订阅与前端 vitest 覆盖，
   e2e_m2.sh 无 GUI。）
4. 前端（vitest）：read/export 弹窗渲染、记住按钮触发 `rule.add`、export
   无记住按钮。

## 11. 交付切分

建议 PR 序列（各自出口全绿，走 PR CI 门禁）：

1. **PR A（lk-core）**：`Rule.capability` + 读规则匹配 + `ApprovalKind` +
   `ERR_AUTHZ_DENIED` + 单测（§10.1）；
2. **PR B（lk-daemon）**：策略表 + begin/finalize 编排 + 审计 + 集成测试
   （§10.2，可与 A 合并为一个 PR 若体量允许）；
3. **PR C（lk-cli + E2E）**：`rule add --read`、拒绝文案、e2e 扩展（§10.3）；
4. **PR D（前端 + 收尾）**：弹窗 kind + 记住按钮 + vitest + 文档收尾
   （authorization-gate §8 状态翻转「已实现」、milestones M2.9 勾选、
   **关闭 #65**）。

## 12. 开放问题（默认值已定，改动需重新拍板）

- **锁态读一体化（#67 同款）**：默认不做。理由：读值场景人在 GUI 前本就
  可看全库，CLI 锁态读取引导先解锁即可；把「临时解锁」面扩大到读通道会
  增加 #65 关切的能力面，收益小。
- **key 名通配**：默认不做（read 规则 keys 精确名），与 inject 语义一致；
  需要时按 glob 扩展另行拍板。
- **记住按钮默认态**：默认不勾选，用户显式选择授权持久化。
- **strict 元数据隐藏**（`item.list`/`rule.list` 名称也不给 socket 通道）：
  留作未来旋钮，本项不做。
