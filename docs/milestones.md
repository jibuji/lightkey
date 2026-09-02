# 里程碑（M0–M3）

- 状态：已拍板（D3）；M1.5 插件化改造为船长插件化定案新增（已落地，见 §M1.5）
- 实现顺序严格执行；每个里程碑有明确出口标准，完成后按 [testing.md](testing.md)
  验收并交付。
- 关联：[plugin-architecture.md](plugin-architecture.md)（M1.5 起）·
  [architecture.md](architecture.md)（边界）· [decisions.md](decisions.md)（决议）

## 编号说明（2026-08 插件化定案）

- M0（单机闭环）、M1（同步）**已完成，现状不重写**。
- 新增 **M1.5 —— 插件化改造**，插入 M1 之后、M2 之前。
- 新增 **M2.75 —— 跨子系统 stdio 桥**（补充拍板 #14），插入 M2.5 之后、M3 之前；
  完整规格见 [cross-subsystem.md](cross-subsystem.md)。
- 新增 **M2.95 —— 规则管理审批门**（补充拍板 #22，issue #104），插入 M2.9
  之后、M3 之前；规则建立/撤销升为桌面审批事件（authorization-gate.md §9）。
- **M2 / M3 标签保持不变**：M2 = Agent 授权门 + 桌面端（在插件化骨架上），
  M3 = 浏览器填充（V1 之后）。此编号方案避免波及其它文档的 M2/M3 引用，
  并已落地（M1.5 独立里程碑已完成）。

## M0 —— 骨架 + 单机闭环（已完成）

**目标**：不经任何网络，一个人在本机完成「建库 → 解锁 → 增删改查 → 锁定 →
恢复」的完整闭环，并产出本地审计。

范围：

- Rust workspace 骨架（已完成）+ `lk-core` 实现：
  - 加密原语与自描述密文格式（[crypto.md](crypto.md)）
  - 数据模型：条目 CRUD、加密索引、CAS、墓碑（[data-model.md](data-model.md)）
  - 解锁/锁定与会话（[ipc.md](ipc.md)）
  - 恢复信封（[recovery.md](recovery.md)）
  - 本地审计（[audit.md](audit.md)）
- CLI：`lk init` / `unlock` / `lock` / `item`（CRUD）/ `audit` / `daemon` / `status`（[cli.md](cli.md)）
- 守护进程解锁态 + 本地 IPC（JSON-RPC 2.0）可用。

**出口**：核心单元 + 属性测试过（加密往返、CAS 冲突、墓碑收敛）；CLI 端到端
脚本走通单机闭环；Windows 冒烟通过。

## M1 —— 同步（BYO 变更发现 + CAS + 墓碑）（已完成）

**目标**：两个客户端通过 BYO 存储（WebDAV / S3 无服务器）最终一致。

范围：

- 存储端零知识布局（密文文件，文件名纯 UUID 无时间戳，见 [data-model.md](data-model.md)）
- 加密索引 + 轮询变更发现（默认 60s，可配 15s~3600s（1h）），静默、无中间态加载
- CAS 上传 + 冲突收敛（last-write-wins）+ 墓碑同步与 30 天延迟硬删
- `lk sync` / `lk config` 同步配置（[cli.md](cli.md)）

**出口**：E2E 双客户端冲突合并用例通过（见 [testing.md](testing.md)）；轮询代价
在 [sync.md](sync.md) 中如实记录。

## M1.5 —— 插件化改造（Cordis）（已完成）

**目标**：按 [plugin-architecture.md](plugin-architecture.md) 落地插件化架构——
Rust 核心按 A/B 层边界重组（trait 服务 + 事件总线，**行为不回归**），D 层 TS 用
真 Cordis 搭建宿主 + 首批插件（theme + ipc-bridge + preference-store + ui 骨架），
并落地槽位机制 + `cordis.yml` 装配。

范围：

- Rust 核心（`lk-core`）按 A/B 层边界重组：crypto / vault-store / recovery / audit /
  session（A 层）+ storage-backend / sync-engine（B 层）→ trait 服务 + 事件总线
  （模拟 Cordis 语义，见 plugin-architecture.md §3/§5）。
- C 层 daemon 宿主：装配 A/B、IPC 路由、空闲自动锁定、config.json 读写
  （现有 daemon 模块按此边界整理，行为不变）。
- D 层 TS：引入真 Cordis（`@cordisjs/core` 4.x）+ `cordis.yml` + loader +
  `@cordisjs/schema`；首批插件 theme + ipc-bridge + preference-store；React 宿主
  薄层（三栏骨架 + 槽位挂载 + 事件重渲染）。
- 槽位机制：`topbar`/`sidebar`/`content` 固定骨架 + 组件 `slot` 声明 + 布局数据。
- 事件总线契约落地：`item.changed` / `session.unlocked` / `session.locked` /
  `theme.changed` / `clipboard.copied`（`authz.request` 留待 M2 随 authz-gate 接入）。

**出口**：

- **行为不回归**：现有 M0/M1 全量测试（[testing.md](testing.md) 第一层 + E2E
  双客户端脚本 `scripts/e2e_m1.sh` / `scripts/e2e_m0.sh`）在重组后全绿；密文格式、
  存储布局、IPC 协议零变更（旧库可无损解锁）。
- D 层宿主可用：`cordis.yml` 装配首批插件 + 槽位骨架渲染，theme 暗/浅切换与
  偏好持久化（preference-store）走通，ipc-bridge 的 mock 适配器在无 Tauri 环境
  可跑通 ui 骨架。
- 事件总线：`item.changed` 三方响应、`session.unlocked/locked` 切换、`theme.changed`
  重渲染、`clipboard.copied` Toast + 30s 清除，均有单测/属性测试覆盖。

> 本里程碑已作为独立里程碑落地（编号 M1.5，见 [plugin-architecture.md](plugin-architecture.md) §10.1）。

## M2 —— Agent 授权门 + 桌面端（已完成）

**目标**：`lk inject` 三层授权可用；桌面应用完整可用（在 M1.5 插件化骨架上实现）。

范围：

- 授权门三层模型 + 启动者判定 + 规则库（`lk rule add` + 桌面规则管理页，
  见 [authorization-gate.md](authorization-gate.md)）——落在 authz-gate 插件（B 层）。
- 审批通道接口化（本地实现；远程留接口，P1 不做）——approval 插件（D 层）
  弹窗 + 30s 倒计时；`authz.request` 事件接入（plugin-architecture.md §5）。
- Tauri 壳接入：窗口、IPC 桥、解锁/锁定联动、审批弹窗、托盘——desktop-shell 插件。
- React 前端按 [design/spec.md](design/spec.md) 实现（解锁/条目/规则/设置/审计）——
  在骨架上实现 ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit 插件。
- 主题（theme 插件）与设计 tokens 接入实际界面；锁屏/超时自动锁定。

**出口**：授权门安全专项用例通过（绕过尝试、审计篡改检测）；Windows 验收；
M1.5 行为不回归仍保持（插件化骨架上新增功能不破坏既有闭环）。

## M2.5 —— 首次初始化向导（已完成）

**目标**：全新安装的桌面端首次启动进入初始化向导（而非直接显示解锁页）：
设主密码 → 展示恢复码（仅一次）→ 完成并解锁进入主界面。

范围：

- 首启检测：`vault.status` 新增 `initialized`（库是否已初始化）——Tauri 壳
  启动时先查库状态：无库 → 初始化向导；有库 → 正常解锁页（互斥门控）。
- 主密码策略留 Rust（安全核心不搬出）：`vault.init`/`vault.recover` 校验
  最小长度（至少 8 位，`vault.weak_password`）；弱密码/已存在库 UI 统一
  文案不区分（[ipc.md](ipc.md) §3 防探测语义）。
- 初始化向导（ui-onboarding 插件，忠实 [design/spec.md](design/spec.md)
  原型四步）：欢迎 → 设主密码（强度条 + 两次一致校验）→ 真实恢复码展示
  （仅 init 响应一次；勾选「我已保存」门控）→ 完成 unlock 进入主界面。
- 恢复码生成/信封/建库全部复用既有 `vault.init` 协议（[recovery.md](recovery.md)）。

**出口**：全新环境启动 → 向导（四步）→ 完成 → 已解锁主界面；有库环境
启动 → 解锁页（回归）；前端单测覆盖四步流（弱/强/不一致、checkbox 门控、
完成跳转）+ Rust 库状态检测单测（无库/有库）；`cargo test` + vitest +
clippy/fmt 全绿；agent_browser 跑通「首启→向导→完成→解锁」全流程。

## M2.75 —— 跨子系统 stdio 桥（已完成）

**目标**：WSL2 内 Linux 原生应用（含 agent 工具链）经 `lk` 命令连接同一台
Windows 主机上的 LightKey 桌面守护实例——查看条目、请求授权、向 **Linux
子进程**注入被批准的密钥，全程可审计、默认拒绝语义不变。完整规格见
[cross-subsystem.md](cross-subsystem.md)（补充拍板 #14）。

范围：

- interop stdio 桥：`lk.exe bridge`（Windows 侧中继，一进程一请求，随桌面
  包装入安装目录）+ Linux `lk` 传输抽象（local / bridge 后端选择；
  `LIGHTKEY_BRIDGE` 探测分型——装了连不上明确报错、没装静默本地，绝不静默
  回落防空库错觉；连接目标可见：stderr 提示 + `lk status` 目标字段）。
- 协议版本校验（主.次一致，fail-closed，绝不静默降级）；`daemon.json` 可选
  `version` 字段（旧文件缺省可读）。
- `lk-core::path_ns` projectDir 跨命名空间归一化（UNC/verbatim →
  `wsl://<distro>/…` 规范形；规则入库与运行时判定两侧同函数）+ 审计
  `channel=wsl-bridge` 标注；前端弹窗/规则列表 `wsl://` 形态标注 (WSL)。
- 发布流水线：Linux `lk` 产物 + 桌面包 bundle.resources 捆绑 `lk.exe`；
  `scripts/e2e_cross_subsystem.sh`（宿主无 WSL 干净跳过，CI 不阻塞）。

**出口**：`path_ns` 归一化 / bridge 帧透传字节保真 / 版本校验三态单测 + 授权门
绕过清单增补四项（见 [authorization-gate.md](authorization-gate.md) §7）+
跨子系统 E2E（见 [testing.md](testing.md) 第四层补充）；五文档回填
（ipc / authorization-gate / cli / architecture / testing）；Windows 桌面包
安装目录含独立 `lk.exe`（修复装机目录缺失 CLI 的前科，cross-subsystem.md §4#7）。

> 本里程碑为补充拍板 #14 新增（插入 M2.5 之后、M3 之前），已完成。

## M2.8 —— 锁定态 inject 一体化（临时解锁 + 本次授权为一次交互）（已完成）

**目标**：issue #67（锁定态 `lk inject` UX 断层）与 #65（inject 后顺手获得
全量令牌）按补充拍板 #19 实现——库锁定且桌面审批界面在场时，把「临时解锁 +
本次授权」折叠为 GUI 上的一次交互；headless 维持 fail-closed。

范围：

- 协议/Rust：`ApprovalResultParams.masterPassword`（可选）、
  `ApprovalRequest.needs_unlock` 与 `authz.request` 帧 `needsUnlock`；
  daemon 锁态 `authz.evaluate` 走一体化（`authz_begin` 锁态分支 +
  `authz_finalize_unlock` 在临时 vault 上跑完整三层）；desktop 来源 `subscribe`
  允许锁态订阅。
- 前端：approval 插件 `needsUnlock` 弹窗（主密码输入栏 + 解锁并允许 + 错误
  停留可重试）；`ensureSubscribed` 启动即订阅；mock 适配器支持锁态一体化。
- 审计两条：`vault.unlock`（channel=desktop / via=inject-gui）+ `lk inject`
  （channel=approval），用临时 vault 的 K_audit 签名。
- 锁态一体化**不签发会话令牌 / 不写 session.token / 不置 shared.vault**——
  临时解锁材料只服务本次注入，不产生 item.* 全量读能力（#65 配套）。

**出口**：`cargo test`（lk-core/lk-daemon/lk-cli 三 crate）+ vitest 全绿；M0/M1
/M2 E2E 回归通过；clippy/fmt 全绿；文档同步（decisions #19、authorization-gate
§5.1/§6/§7、ipc §4.1、cli §4、milestones）。

> 本里程碑为补充拍板 #19 新增（插入 M2.75 之后、M3 之前），已完成。

## M2.9 —— 值披露裁决：item.get / item.export 能力面（已完成）

**目标**：issue #65 主体，按补充拍板 #20 落地——安全边界修订为
**产品接口面即边界**（令牌 = 认证 ≠ 授权），`item.get` / `item.export`
从「持令牌即返回明文」升为裁决方法。**实现规格见
[value-disclosure.md](value-disclosure.md)**（判定矩阵、读规则 schema、
RPC/执行计划、CLI/前端、审计、测试计划、PR 切分）。

范围（细节以 [value-disclosure.md](value-disclosure.md) 为准）：

- lk-core：`Rule.capability` + 读规则匹配 + `ApprovalKind` + `authz.denied`
  错误码（spec §4/§5.4）；
- lk-daemon：`strategy_of` 升级两方法 + begin/finalize 裁决编排 + 审计
  （spec §5/§8）；
- lk-cli + E2E：`rule add --read`、拒绝文案、e2e_m2.sh 场景（spec §7/§10.3）；
- 前端：弹窗按 kind 渲染 + 「允许并记住」存读规则（spec §6）。

**出口**：`cargo test` + vitest 全绿；M0/M1/M2 E2E 回归 + spec §10 新增
断言通过；clippy/fmt 全绿；文档同步（spec 状态翻转、authorization-gate
§8、milestones）；**#65 关闭**。

**落地记录**：单 PR 交付（lk-core/lk-daemon/lk-cli/前端/e2e 一次合入）。
实现与 spec 的两处偏差见 spec 注记：`authz.denied` 错误码取 **-32017**
（spec 原定 -32015 已被 `ERR_BRIDGE_*` 占用，§5.4）；read 规则 CLI 形态为
`--read --keys <name...>`（clap 位置参数贪婪性，§7）。e2e_m0/m1 同步适配：
headless 读值经 `rule add --read` 预授权（条目名改 env 安全名）、headless
export 转为恒拒绝断言（附件往返由 lk-core/daemon 测试覆盖）。

> 本里程碑为补充拍板 #20 新增（插入 M2.8 之后、M3 之前）。

## M2.95 —— 规则管理审批门 + 读通道一体化解锁（rule/读审批）（已完成）

**目标**：issue #104 与 #105，按补充拍板 #22/#23 落地——socket/pipe 通道的
`rule.add` / `rule.remove` 从「仅验会话令牌」升为**桌面审批门**（对称原则：
授权的建立与撤销都是授权事件），headless fail-closed，GUI desktop 直调
豁免；配套 E2E 自动批准通道与全路径审计。**读通道一体化解锁**：锁定态 +
桌面 UI 在场时 `item.get` / `item.export` 弹「主密码 + 解锁并允许」一体化
窗（临时 vault 单次披露即毁、无痕）。实现规格见
[authorization-gate.md](authorization-gate.md) §9（规则门）/ §5.2（读通道
一体化）与 [value-disclosure.md](value-disclosure.md) §3/§5。

范围（规则门，issue #104）：

- lk-core：`ApprovalKind::Rule`（serde `"rule"`，加性变更不升协议版本）+ 单一
  kind + command 字段承载操作（`rule.add <name>` / `rule.remove <name>`）；
  `ApprovalChannel` 新增 `auto_approves` 默认假 + `AutoApproveChannel`
  （env 门控装饰器，`LIGHTKEY_E2E_AUTO_APPROVE=rule` 仅对规则审批立即放行）；
  审计 `AuditChannel::AutoApprove`（`channel=auto-approve`）。
- lk-daemon：`strategy_of` 升 `rule.add` / `rule.remove` 为 ApprovalDeferred
  （`rule.list` 维持 Inline）；`rule_begin`（参数校验/归一化 + id→规则解析
  补全 + desktop 豁免 + fail-closed 登记/广播）→ 锁外等待 → `rule_finalize`
  （**锁内 TOCTOU 重校验** vault 解锁态 + 规则存在性，失效拒绝落审计）；
  失败路径审计（denied/timeout/no_ui/unknown starter）。
- lk-cli：规则门拒绝（-32017）按命令上下文渲染「规则变更被授权门拒绝…」
  （`rpc_fail_ctx`；机器契约 error 名不变）。
- 前端：approval 插件 kind=rule 分支（命令框 + keys Tag + 30s 倒计时，无
  「记住」按钮）+ **未知 kind 防御渲染**（不回退 inject）；events.ts kind
  联合类型更新。
- E2E：`e2e_m0/m1/m2/cross_subsystem.sh` 传 env 保持主流程（规则预插经
  自动批准放行）；`e2e_m2.sh` 新增「无 env 时 headless rule add 被拒」
  断言 + auto-approve 审计断言。

范围（读通道一体化，issue #105）：

- lk-daemon：披露预检分流（未初始化/headless fail-closed；initialized &&
  锁态 && 有 UI → 登记 `Pending{needs_unlock:true}`）；finalize 复用 #67
  `approval_result_unlock` 临时 vault 编排，在临时 vault 上执行披露
  （get/export exec 支持传入 vault 引用）+ 审计（channel=approval）。
- 前端：读/导出 + needsUnlock 组合渲染（主密码栏复用、「解锁并允许」）；
  **「记住」按钮渲染条件 = `isRead && !needsUnlock`**（锁态 read 弹窗无
  记住按钮，D 层单测钉住）。
- 集成测试：锁态 get/export 全流程、密码错重试、**临时 vault 无痕断言**、
  等待期锁定/解锁竞争、锁态 read 规则命中仍必弹窗、未初始化库 fail-closed。

**出口**：`cargo test` + vitest 全绿；M0/M1/M2/M2.75/M2.8/M2.9 E2E 回归 +
规则门集成测试（tests/rule_gate.rs）+ 读通道一体化集成测试
（tests/disclosure.rs 锁态用例组）通过；clippy/fmt 全绿；文档同步
（decisions #22/#23、authorization-gate §5.2/§9、value-disclosure §3/§5、
milestones、AGENTS.md、CONTEXT.md）；**#104/#105 关闭**。

> 本里程碑为补充拍板 #22/#23 新增（插入 M2.9 之后、M3 之前）。

## M2.97 —— 写入授权门（write gate）（已完成）

**目标**：补充拍板 #24（2026-09-02 write-gate grilling 拍板）——`item.put`
（create/update）与 `item.delete` 从「仅验会话令牌」升为裁决方法（对称原则
完成面：值披露是授权事件（#20），写入同样是授权事件）；完备的判定矩阵、
写规则（capability=write + actions）、delete 恒弹窗。实现规格唯一出处
[write-gate.md](write-gate.md)。

范围（按 [write-gate.md](write-gate.md) §11 的 PR 序列）：

- lk-core：`Rule.actions`（serde 缺省 `["create","update"]`）+ 写规则双向
  名称匹配（create 草稿名 ∈ keys；update 存储名 ∧ 草稿名 ⊆ keys）+ 能力
  三向不互授 + `ApprovalKind::Write`（serde `"write"`，加性变更不升协议
  版本）。
- lk-daemon：`strategy_of` 升 `item.put` / `item.delete` 为 ApprovalDeferred
  （`item.list` 维持 Inline)；`M_ITEM_PUT` RPC **不拆**（action 由 daemon
  从 `ItemPutParams.id` 有无权威派生；内部处理函数拆 create/update exec）；
  begin/finalize 编排复用规则门模式（desktop 豁免 / 写规则命中静默 /
  弹窗 / headless `authz.denied`；finalize 锁内 TOCTOU 重校验）；delete
  **恒弹窗**任何规则不豁免；锁态 `session.invalid` 先行；全路径审计。
- lk-cli：`rule add --write [--actions create,update]`（省略 command）；
  写拒绝按命令语境渲染文案（-32017 复用）；`--json` 契约 error 名不变。
- 前端：approval 插件 kind=write 分支（动作 + 目标条目名 + 30s 倒计时，
  不展示值）；「记住」按钮仅 create/update（生成 `keys=[条目名] +
  actions=[当前动作]` 最小写规则），delete 无记住按钮；规则管理页展示
  capability + actions。
- E2E：**不扩展** auto-approve 到写门——shell E2E 覆盖 headless 拒绝 /
  写规则命中静默（`auto-approve=rule` 预插）/ delete 恒弹窗拒绝；弹窗
  批准路径由 daemon 集成测试（`LocalApprovalChannel`）覆盖。

**出口**：`cargo test` + vitest 全绿；M0/M1/M2/M2.75/M2.8/M2.9/M2.95 回归 +
写门集成测试（tests/write_gate.rs）通过；clippy/fmt 全绿；文档同步
（write-gate.md、authorization-gate §10、ipc/cli/agent-cli/data-model/
milestones、decisions #24 状态翻转、AGENTS.md、CONTEXT.md）；写门 issue
立项并关闭。

> 本里程碑为 write-gate grilling 会话拍板（补充拍板 #24）新增（插入
> M2.95 之后、M3 之前）；已按 write-gate.md §11 PR A-D 序列落地
> （issues #112-#115）。

## M3 —— 浏览器填充（V1 之后）

**目标**：浏览器扩展按 [browser-fill.md](browser-fill.md) 协议实现。

范围：

- Chrome 扩展（Native Messaging）+ 桌面已解锁会话取凭据填充——browser-fill 插件（D 层）。
- 填充置灰 + 快速解锁弹窗；剪贴板 30s 自动清除；只填充主动点击的输入框。

**出口**：扩展在桌面锁定/未运行时正确置灰；填充与剪贴板行为通过验收。
