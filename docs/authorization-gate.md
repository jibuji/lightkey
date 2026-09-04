# Agent 授权门规格（authorization-gate，M2）

- 状态：已拍板（D8）
- 关联：[ipc.md](ipc.md)（最小字段响应）· [audit.md](audit.md)（事件留痕）
  · [design/spec.md](design/spec.md)（审批弹窗 / 规则管理页）

## 1. 问题与目标

Agent（AI 编码助手等）在工作目录执行命令时，可能请求访问用户密钥。授权门的
目标是：**默认拒绝**；只有显式授权才放行；**任何放行都可审计、可回溯**。

## 2. 三层模型（D8）

```
① 默认拒绝（default-deny）
    启动者未知 / cwd 不可得 / 规则库损坏 / 请求 key 无法解析 → 拒绝
    （不弹窗、不留内容，仅审计“拒绝”事件）
        │ 命中白名单？
        ▼
② 规则白名单（vault 内加密、按项目目录绑定）
    命中 → 直接放行（只注入该规则授权的 key 名）
    未命中 → 进入弹窗审批
        ▼
③ 弹窗审批（30 秒超时默认拒绝）
    用户明确允许 → 本次放行
    超时/拒绝 → 拒绝 + 审计
```

- **agent 只能看到被授权的 key 名**（承诺范围，补充拍板 #20 修订）：在
  **inject 通道内**严格成立——规则白名单决定注入集合，未授权 key 名对
  走 inject 的 agent 不可见。**持令牌进程可见条目/规则元数据**
  （`item.list` 的名称、`rule.list` 规则内的 key 名）；**值的披露是一个
  授权事件**——读规则命中或弹窗批准（§8，已实现）。
- 三层每一层的结果都写入审计（[audit.md](audit.md)），含超时。

## 3. 启动者判定（D8）

- 判定依据 = **进程链回溯 + 工作目录**：
  - 回溯发起进程的父进程链（如 `shell → agent → tool`），确定**启动者**
    （可归属的顶层进程，如终端/编辑器/agent 进程）。
  - 工作目录 = 发起命令时的 cwd，用于匹配「项目目录绑定」的规则。
- 实现：macOS/Linux 走 procfs/sysctl 进程树；Windows 走 Toolhelp32 快照枚举进程
  + 读 PEB 取对端 cwd；回溯失败（权限/跨会话）→ 视为未知启动者 → 默认拒绝
  （fail-closed）。
- 已知限制：macOS 的对端 cwd 解析（`resolve_peer_cwd`）尚未实现（`starter.rs`
  注释标注），macOS 上 `lk inject` 因无法确认启动者 cwd 会 fail-closed 拒绝。
- **interop 中继链（跨子系统桥，补充拍板 #14）**：WSL 内 Linux `lk` 经
  `lk.exe bridge` 中继连接 Windows 守护进程时，IPC 对端是 bridge 进程，
  其父链为 interop 链 `bridge → wsl.exe → wsl.exe → 终端进程 → …`，Windows
  侧完全可见（本机 Win32_Process 实证），Toolhelp 回溯不会 fail-closed。
  starter 如实展示中继链顶层（如 `wsl.exe`/终端进程名）；cwd 取 bridge 进程
  PEB 真实 cwd（interop 继承的调用方项目目录 UNC），足以定位项目。审计
  `channel = wsl-bridge`。详见 [cross-subsystem.md](cross-subsystem.md) §7.5。
- 结果用途（与代码一致，`crates/lk-core/src/authz.rs` `evaluate_layers`）：
  `starter` 只用于审计字段与第 1 层兜底（unknown → fail-closed），**不参与
  规则匹配**——规则命中仅看 `capability` + 项目目录（cwd，ancestor 匹配）+
  command glob / keys，任何同用户进程在授权目录内复现授权命令形态即可命中；
  `cwd` 供规则匹配与审计两用。

## 4. 规则库（D8）

- **规则入库、加密存储**：规则是 vault 内加密对象（K_data），随库同步
  （见 [data-model.md](data-model.md) §2 对象表，新增 `rule` 类型）；规则的
  跨端变更发现与增量同步走同一加密索引/轮询路径（索引覆盖条目与规则，见
  [data-model.md](data-model.md) §6）。
- **按项目目录绑定**：每条规则绑定一个项目目录（路径匹配，支持通配/祖先匹配），
  如 `~/work/proj-a`；规则只在该目录下生效。
- **规则字段**：
  ```jsonc
  {
    "id": "<uuid>",
    "projectDir": "~/work/proj-a",
    "name": "publish",
    "command": "npm publish",              // 具名命令（可 glob）
    "keys": ["NPM_TOKEN"],                  // 授权注入的 key 名（最小集合）
    "created": "<ISO-8601>"
  }
  ```
- **两条写入路径**（D8，唯一合法路径）：
  1. `lk rule add`（CLI，见 [cli.md](cli.md)）
  2. 桌面「规则管理页」（M2，见 [design/spec.md](design/spec.md)）
- **不开放手动改加密文件**：规则文件在 vault 内加密，用户无明文编辑入口；
  变更必须走上述两路之一（保证一致性 + 审计可查——规则变更也写审计）。

## 5. `lk inject` 语义（D8）

- 形态：`lk inject --keys <name...> -- <command...>`（`--keys` 必需），如
  `lk inject --keys NPM_TOKEN -- npm publish`。
- **`--keys` 语义**（#69 澄清）：key 名 = 库内 **secret 类型条目**的名称
  （决策 #1 A 的「密钥」即 secret 条目）；login/note/file 条目不支持注入，
  请求后按第 1 层 `missing_keys` 拒绝——与「不存在」**不区分**（不泄露库内
  有哪些 key / 某名字是否为不可注入类型条目；防枚举）。login 条目字段映射
  注入（如 `name.password`）属未拍板的产品缺口，见 issue #69。
- 行为：
  1. 进程链回溯 + cwd 判定启动者与项目目录。
  2. 查规则白名单：命中 → 注入该规则授权的 env 变量集（值来自 vault 解密，
     **最小字段**，见 [ipc.md](ipc.md)）。
  3. 未命中 → 弹窗审批（本地弹窗，30s 超时默认拒绝；审批通道可切换，见 §6）。
  4. 允许 → 以「原命令 + 注入 env」启动子进程；拒绝/超时 → 非零退出 + 审计。
- **锁定态一体化（#67，补充拍板 #19）**：库处于**锁定态**时收到 `authz.evaluate`
  （即 `lk inject`），若桌面审批界面在场（desktop 推送订阅存在，`has_ui`），
  把「临时解锁 + 本次授权」折叠为 GUI 上的一次交互——见 §5.1。

### 5.1 锁定态：临时解锁 + 本次授权一体化（#67）

- **触发**：锁定态收到 `authz.evaluate`（`lk inject`），且 `has_ui`（桌面来源的
  推送订阅存在；非 socket 订阅者）。**GUI 不在运行（纯 headless）** → 维持现状
  fail-closed `session.invalid`（CLI 提示先解锁；不阻塞、不静默回落）。
- **一次性交互**：守护进程登记待审批（`needs_unlock=true`）+ 广播
  `authz.request`（帧带 `needsUnlock=true`）→ 桌面弹窗同时展示：
  - 身份确认栏：主密码输入框（M2 中 Windows Hello 预留，决策 #5 B，见 §6）；
  - 行为授权栏：启动者 / 项目目录 / 目标命令 / 请求 key 名 / 倒计时。
- **用户一次性完成**：输入主密码（临时解锁）+ 点 Allow/Deny（本次授权）。
- **守护进程侧**：
  1. `approval.result`（allowed）须携带 `masterPassword`——先做**临时解锁**
     （`UnlockedVault::unlock`，AuthGuard 限流照常生效，审计 `vault.unlock`
     channel=desktop / via=inject-gui）；主密码错误 → `ERR_VAULT_INVALID`（统一
     文案防探测），条目保留、弹窗停留可在倒计时内重试（AuthGuard 记失败计数）。
  2. 解锁成功才 `resolve(Allowed)`；finalize 时在**临时 vault** 上跑完整三层
     （锁态 begin 无法预载规则/解析 key）+ 解析 env + 审计 `lk inject`
     （channel=approval，用临时 vault 的 K_audit 签名）。
  3. **关键约束**：临时解锁材料只服务本次注入——不签发会话令牌、不写
     `session.token`、不置 `shared.vault`；临时 vault 随 finalize 结束即销毁，
     vault 保持锁定，**不产生 item.* 全量读能力**（#65 配套）。
- **拒绝/超时且未解锁**：无临时 vault → 无 K_audit 可签名，**不写审计**
  （与 v0 锁态拒绝同口径——fail-closed 不留审计内容）。
- **密钥只注入被批准具名命令的进程环境**：
  - 注入的是子进程环境变量，**绝不进入模型对话环境**（agent 无法通过
    stdout/日志拿回未授权值；agent 拿到的只有「已注入/已拒绝」）。
  - env 变量名（key 名）对 agent 可见，值不可见——除非该 key 已授权。
- 示例：`NPM_TOKEN=... lk inject --keys NPM_TOKEN -- npm publish` 的等价效果（但经授权门裁决）。
- 内建脱敏：注入值在审计/命令摘要中永不明文（见 [audit.md](audit.md) §2）。

### 5.2 读通道一体化：锁定态 `item.get` / `item.export`（#23，补充拍板 #23）

> §5.1 的机制扩展到**值披露**（读通道）——锁定态 + 桌面 UI 在场时，
> `item.get` / `item.export` 弹「主密码 + 解锁并允许」一体化窗，一次交互
> 完成（临时解锁 + 本次披露），临时 vault 单次披露即毁、无痕。完整规格见
> [value-disclosure.md](value-disclosure.md) §3 锁态行 / §5.2-5.3（唯一出处）。

- **触发**：锁定态收到 `item.get` / `item.export`，且库**已初始化** +
  `has_ui`（桌面来源推送订阅在场）→ 登记 `Pending{needs_unlock:true}` +
  广播 `authz.request(needsUnlock=true)`（协议零新增：`needsUnlock` /
  `masterPassword` / `kind` 三要素即 #67 已就位）。未初始化库 / 无 UI →
  fail-closed `session.invalid`（不弹窗）；解锁态行为零变化。
- **锁态必弹窗**：即使该条目已有 read 规则命中也必弹——规则在加密库内
  无法预载（与 #67 inject 同款妥协）。文档明示「锁态下一切披露都要一次
  交互」。
- **一次性交互**：弹窗同时展示主密码输入栏（身份确认）+ 行为授权栏
  （启动者 / 项目目录 / kind 形态 / 倒计时）。用户一次性完成 临时解锁 +
  本次披露。
- **守护进程侧**：
  1. `approval.result`（allowed）须携带 `masterPassword`——`approval_result_unlock`
     先做**临时解锁**（#67 同款编排；AuthGuard 限流照常、审计 `vault.unlock`）；
     主密码错误 → `vault.invalid` 统一文案防探测、条目保留、弹窗倒计时内可
     重试；
  2. finalize 在**临时 vault** 上执行披露（get/export exec 支持传入 vault
     引用）+ 审计（channel=approval，用临时 vault 的 K_audit 签名）；
  3. **关键约束**（#65 边界）：临时 vault 即用即毁——不签发会话令牌 / 不写
     `session.token` / 不置 `shared.vault`，本次交互不产生任何持久能力。
  4. **等待期竞争**（与 #67 同口径）：整库被解锁（用户绕开弹窗直接解锁）→
     finalize 走**常态路径**（共享 vault 披露 + 审计）；被锁定 → `session.invalid`。
- **前端**：主密码栏复用、「解锁并允许」按钮；**「允许并为此项目记住」渲染
  条件 = `isRead && !needsUnlock`**——锁态 read 弹窗无记住按钮（临时 vault
  无法持久化规则），D 层单测钉住。
- **已知限制**（补充拍板 #23 留档）：锁态下 agent 循环重试可致弹窗轰炸
  （每个 pending 30s 超时默认拒）；同 (starter, 条目) 合并去重 + 并发上限/
  限流为后续可选加固，不阻塞本规格。

## 6. 审批通道抽象（D8）

- 审批通道 = 接口（trait）`ApprovalChannel`（本地/远程可切换）；两阶段接口
  对应守护进程的 G1 三阶段编排（`authz.evaluate` 锁内登记 → 锁外等待 → 重取锁
  收尾）：
  - `available()` — 是否有界面可能响应审批（**桌面来源的推送订阅存在**；
    #72/#78：socket 订阅者不计——任何持令牌进程都能建立 socket 订阅，
    「有订阅」不等于「有人类可批准」）；`false` → fail-closed 立即拒绝
    （不登记、不阻塞）。
  - `open(req, expires_at)` — 登记待审批（含一次性 challenge）+ 广播
    `authz.request`（命令锁内、非阻塞）。
  - `await_decision(request_id, expires_at)` — 命令锁外等待决策，返回
    `Allowed` / `Denied` / `Timeout`（到期默认拒绝）。
- **信任绑定（#72/#78，补充拍板 #16）**：审批提交与通知投递按连接来源收紧，
  双重防线：
  - **方案 A · 连接标签**：订阅登记带来源标签（桌面内嵌直调 / socket 流连接）；
    `approval.result` 仅接受**桌面内嵌直调**提交——socket/pipe 连接一律以
    专用错误码 `channel.forbidden`（-32014）拒绝。据此「持令牌进程自行
    订阅 + 自行回传批准」的路径闭合。
  - **方案 B · 一次性 challenge**：`open` 时生成高熵随机挑战，仅随
    `authz.request` notification 帧**投递给桌面订阅者**（socket 订阅者不收
    该帧）；回传必须原样带回，错值 → `accepted=false` 且待审批条目保留
    （伪回传不能打掉真审批）。纵使未来出现可伪造连接标签的进程内组件，
    无挑战值仍无法自我批准。
  - 失败提交（伪造 id / 过期 / 挑战不符 / socket 来源被 `channel.forbidden`
    拒绝）写审计（command=`approval.result`，starter/channel 取对端归因）；
    成功提交由第 3 层 finalize 路径审计（channel=approval），不重复记。
- **本地通道**（V1）：桌面弹窗/系统通知，30s 超时默认拒绝。
- **远程通道**（未来，P1 不做）：远程审批中继 = 未来服务端付费点；本阶段
  只留接口与类型，不实现。
- 弹窗内容（最小展示）：启动者、项目目录、目标命令、请求的 key 名、
  倒计时；不展示密钥值。**锁定态一体化帧（`needsUnlock=true`，#67）额外展示
  主密码输入栏**（身份确认），见 §5.1。
- **锁态订阅**（#67）：desktop 来源的 `subscribe` 允许在**锁定态**建立推送流
  （推送目标注册；桌面直调无 IPC 对端，无需会话令牌），使锁态 `authz.request`
  帧能到达 GUI。帧无密钥值（仅 key 名/命令摘要/启动者元数据），锁态订阅不泄露
  明文；socket 订阅照旧要求有效会话。

## 7. 安全约束与测试要点

- fail-closed：启动者未知 / 规则库损坏 / 守护进程无界面 → 一律拒绝。
- **安全边界（补充拍板 #20 修订，替代原 #15 对 #65 的口径）**：
  **产品接口面即边界**——一切穿过 lk 自己 API 的请求（IPC socket /
  named pipe、桌面内嵌直调、CLI、未来 Native Messaging）都在防护边界内，
  令牌 = 认证 ≠ 授权；绕过产品接口的同用户**原生攻击**（调试器、内存注入、
  键盘钩子、读剪贴板/截屏）在边界外，如实声明只能提高成本（#15 前半、
  #17、#18 处置不变）。**当前实现状态**：值披露裁决（§8）已实现（M2.9）——
  `item.get` / `item.export` 已升为裁决方法，产品接口面即边界；事后归因
  依赖审计真实 starter（已落，#66）；
  - **#67 已闭环**：锁定态 inject 的「先手动解锁再临时授权」UX 断层已解决
    （§5.1，临时解锁 + 本次授权一体化为一次交互，且不签发令牌）。
  - **#65 配套已闭环**：一体化流程不再给调用方顺带签发会话令牌——本次注入
    不产生 item.* 全量读能力（§5.1 关键约束）。
  - **#65 主体（值披露裁决）按补充拍板 #20 立项**：见 §8；#68 选项 2
    （常驻进程持令牌）降级为观望，不与本项捆绑。
- **headless 锁态**：GUI 不在运行（纯 CLI daemon / headless）时锁态
  `authz.evaluate` 维持 fail-closed `session.invalid`（§5.1）。
- 审批通道对抗性测试（#72/#78）：socket 来源提交（即使参数完整正确）→
  `channel.forbidden` 且条目保留；挑战不符 → 忽略 + 条目保留 + 审计；
  仅 socket 订阅者 → no_ui 立即拒绝；authz.request 帧绝不投 socket 订阅者。
- 规则变更（add/list/remove）写审计；规则匹配逻辑单测覆盖 glob、目录绑定。
- 安全专项（[testing.md](testing.md) 第三层）：绕过尝试清单——
  伪造 cwd、符号链接目录、跨会话进程、直连 IPC 调 `authz.evaluate`、
  手动改加密规则文件 → 全部必须失败且留痕。
- 跨子系统桥安全专项（补充拍板 #14，[cross-subsystem.md](cross-subsystem.md)
  §10，实现时逐项验证）：
  - 伪造 `\\wsl.localhost` cwd 变体（大小写 / `wsl$` 别名 / verbatim /
    尾缀）必须经 `path_ns::canonical_project_dir` 归一化后与规则一致匹配，
    不得绕过；
  - interop 被禁用（企业策略，`WSLInterop` 缺失）时必须显式失败并提示，
    不回退到任何未授权路径；
  - 版本不匹配（主.次不一致）必须拒绝服务（`bridge.version_incompatible`），
    绝不静默降级；
  - bridge 进程伪造/复用会话令牌：令牌仍随每次解锁轮换；CLI 跨进程传递经
    数据目录 `session.token`（A1 取舍：unix 0600 / Windows 显式 DACL 仅当前
    用户、锁定即删，生命周期 = 解锁窗口，见 [ipc.md](ipc.md) §3）——同用户
    之外不可读，bridge 中继路径不新增任何持久化。

## 8. 值披露裁决：`item.get` / `item.export` 能力面（补充拍板 #20，已实现）

> **完整实现规格见 [value-disclosure.md](value-disclosure.md)**（唯一出处）；
> 本节只留边界摘要。

- 会话令牌只做**认证**；**值的披露必须是授权事件**——读规则命中或用户
  当场弹窗批准。桌面内嵌直调（`channel = desktop`）受信豁免。
- `item.get` 走三层（读规则 → 弹窗 → 拒绝）；`item.export` **恒弹窗**，
  任何规则不豁免（整条目数据包含附件原始数据，单次披露量最大）。
- 元数据（`item.list` / `rule.list`）维持令牌门（§2 承诺修订）。
- **锁态 + 桌面 UI 在场**：`item.get` / `item.export` 走「主密码 + 解锁并
  允许」一体化弹窗（**锁态必弹窗**，read 规则命中也不豁免——规则在加密库
  内无法预载；headless / 未初始化库维持 fail-closed `session.invalid`）——
  见 §5.2 与 value-disclosure.md §3/§5.2-5.3（补充拍板 #23）。
- 已按规格落地（M2.9）：拒绝错误码实现为 `authz.denied`（-32017，spec
  §5.4 实现注记——-32014~-32016 已被 bridge 错误码占用）；读规则 CLI
  形态 `--read --keys`（spec §7 实现注记）；#65 已闭合。

## 9. 规则管理审批门：`rule.add` / `rule.remove`（补充拍板 #22，已实现）

> 对称原则：授权的建立（agent 给自己 `rule add --read` 持久授权 = 自我
> 提权）与撤销（`rule remove` 删用户既有规则 = 拆墙）都是授权事件——
> §8 的自然延伸。实现：`crates/lk-daemon/src/daemon/rules.rs` +
> `router.rs strategy_of`。

### 9.1 范围与判定矩阵

| 通道 / 状态 | 行为 |
|-------------|------|
| GUI desktop 直调（设置页、读值弹窗「允许并记住」内部 ruleAdd） | 受信豁免，直执行（零摩擦） |
| socket / pipe（CLI、bridge、外部 agent），解锁态 + 桌面 UI 在场 | 弹窗审批（30s 超时默认拒绝） |
| socket / pipe，headless（无桌面订阅） | fail-closed 立即拒绝（-32017，不阻塞） |
| 启动者未知（进程链回溯失败） | fail-closed 拒绝，不弹窗（与 inject 同口径） |
| 锁定态 | `session.invalid` 先行（规则在加密库内；锁态一体化在 Out of Scope） |
| `rule.list` | 维持令牌门（只读元数据，「值是边界」同口径，§8） |

### 9.2 执行计划（ApprovalDeferred 三阶段，ADR-0001）

- **begin（命令锁内，非阻塞）**：参数解析 + 字段校验 + projectDir 归一化/
  canonicalize（与既有 Inline 语义一致，无效参数原错误直返）；remove 顺带
  解析 id→规则补全 name/keys/projectDir（弹窗展示「拆了哪堵墙」）；desktop
  直调豁免直执行；socket 走 fail-closed 检查后登记 `PendingApprovals`
  （challenge 防伪 #78）+ 广播 `authz.request`。
- **锁外等待**（≤30s 超时默认拒绝，G1：不持命令锁）。
- **finalize（重取命令锁）**：**TOCTOU 锁内重校验**——等待窗内规则库可能
  被并发审批落盘或同步轮次改变，vault 解锁态与（remove 的）规则存在性
  （按**未删除**口径——`get_rule` 含墓碑、幂等 delete 会静默成功）失效则
  拒绝并落审计；通过则落盘（`put_rule` / `delete_rule`，`item.changed
  (kind="rule")` 广播照旧）+ 审计。

### 9.3 协议与错误码

- `ApprovalKind` 新增 `Rule`（serde `"rule"`，加性变更不升协议版本）；
  **单一 kind + command 字段承载操作**：`rule.add <name>` /
  `rule.remove <name>`；`keys` = 规则 keys；`projectDir` = 规则项目目录；
  `needs_unlock` 恒 false。
- 拒绝统一复用 **-32017 `authz.denied`**（协议零新增）；CLI 按命令上下文
  渲染「规则变更被授权门拒绝（需桌面审批…）」，与值披露文案区分（同码
  不同命令语境，`--json` 机器契约 error 名不变）。

### 9.4 审计（全路径，已实现）

| 路径 | 审计 |
|------|------|
| desktop 豁免执行 | command=`rule.add <name>` / `rule.remove <id>`，channel=desktop（现状） |
| 弹窗批准 | 同 command，channel=approval，Allowed |
| 弹窗拒绝 / 超时 | 同 command，channel=approval，Denied / Timeout |
| 无 UI / 启动者未知 | 同 command，socket 归因（cli / wsl-bridge），Denied |
| E2E 自动批准 | channel=auto-approve，command 附 `[auto-approve <requestId>]`（含规则内容，绝不静默） |

锁定后（K_audit 擦除）无法签名 → 跳过审计（与授权路径同口径）。

### 9.5 E2E 自动批准通道（AutoApproveChannel）

- `ApprovalChannel` 的 env 门控装饰器：daemon **启动时**读一次
  `LIGHTKEY_E2E_AUTO_APPROVE=rule`，仅对 `ApprovalKind::Rule` 立即 Allowed
  （登记后即刻 resolve，**不广播** `authz.request`——无 UI 参与）；
  `available()` 语义原样透传内层，**inject/披露审批不受影响**（headless
  照旧立即拒绝，不等待）。
- 启用即打 daemon 启动日志横幅；放行留 channel=auto-approve 审计。
- **release 二进制保留此路径是有意决策**（E2E 测发布物本体；编译期
  feature/cfg 门为被否选项）。攻击面：env 仅启动时读取，攻击者自带该变量
  拉起的新 daemon 库是锁的、`rule.add` 仍过会话门，无权限增益。

### 9.6 测试

- daemon 集成（`lk-daemon/src/tests/rule_gate.rs`）：desktop 豁免 / no_ui
  拒绝 / 未知启动者 / pending→批准→落规则 / deny / 超时 / remove 弹窗展示
  解析规则 / 锁态 session.invalid / 等待期锁定 / TOCTOU 竞争 / auto 通道
  （进程内驱动 `LocalApprovalChannel` 模拟桌面订阅）。
- shell E2E：`e2e_m2.sh` 传 env 主流程 + 「无 env 时 headless rule add
  被拒」（独立数据目录另起无 env 守护）+ auto-approve 审计断言；
  `e2e_m0/m1` 传 env（主流程含 rule add 预插）；`e2e_cross_subsystem.sh`
  传 env + WSLENV（Windows 守护实例由桌面应用持有，见脚本头注释）。

## 10. 写入授权门（write gate，M2.97，已实现）

> 完整实现规格见 [write-gate.md](write-gate.md)（**唯一出处**）；本节只留
> 边界摘要（补充拍板 #24，2026-09-02 拍板，已实现）。

- **写 = 授权事件**（值披露裁决 #20 的对称完成面）：`item.put`（create /
  update）与 `item.delete` 从「仅验会话令牌」升为裁决方法（ApprovalDeferred
  三阶段复用）；desktop 直调受信豁免；headless fail-closed（`authz.denied`
  -32017 复用）；锁态 `session.invalid` 先行（规则在加密库内）。
- **写规则**（`capability=write` + `actions`（create/update 子集，缺省
  create+update；**delete 不存在于 actions**——恒弹窗由协议保证，规则写不
  进去））：按条目名匹配——create 草稿名 ∈ keys；update 存储名
  **且** 草稿名都 ∈ keys（双向名称约束：名字不得「进出」授权集合，防改名
  逃生 / 改名植毒）；重名语义 = 名字即身份（覆盖全部同名条目，与读规则
  同构）。**delete 恒弹窗，任何规则不豁免**（无用户级恢复路径）。
- **协议零变更，RPC 不拆**：单一 `item.put`（action 由 daemon 从
  `ItemPutParams.id` 有无权威派生）+ `item.delete`；`ApprovalKind::Write`
  加性新增。
- **边界**：同步应用远端变更不受门（BYO 信任模型维持）；真相源投毒
  （写规则静默改写 secret 值 → 后续合法读/注入拿污染值）= 已知限制（文档
  明示）；exe+哈希身份绑定为整体可选加固，不随本规格。

## 11. 规则程序指纹绑定（identity binding，M2.98，已实现）

> 完整实现规格见 [identity-binding.md](identity-binding.md)（**唯一出处**）；
> 本节只留边界摘要（补充拍板 #25，2026-09-02 拍板，已实现——lk-core /
> lk-daemon / lk-cli+E2E / 前端+收尾 PR 序列落地，issues #123-#126，父立项
> #121）。**read/write 调用方链绑定按 spec §12 默认仅字段预留**——本期只随
> 注入路径落地完整 CLI/UI；读/写规则的调用方链绑定仅文档明示适用边界
> （独立工具二进制场景，终端/IDE/脚本的 starter 不稳定、升级即失配），
> 不落地 CLI/UI（spec §12）。

- **授权目标是程序而非命令形态**：规则**可选**绑定程序指纹（canonical 路径
  + SHA-256 + 固化时大小）——注入规则绑定被注入命令二进制（`command[0]`）、
  读/写规则可选绑定调用方链（限独立工具二进制场景）；未绑定 = 现状语义
  （目录 + 命令形态/条目名，零迁移）。
- **失配 = 未命中**：**不新增错误码**（防探测）；GUI 弹窗明示「程序指纹与
  规则不符（可能已更新）」+「**以新指纹重新授权**」（复用规则管理审批门）；
  headless 统一 `authz.denied`。**前端帧面（M2.98，已实现）**：
  `authz.request` 帧新增可选 `fingerprintMismatch`（`resolvedExePath` 当前
  解析路径 + `sha256Short` 8 位 SHA-256 前缀摘要，**不含完整哈希、任何值或
  错误码差异化**）；弹窗据此渲染失配主题 + 路径 + 摘要 +「本次允许 / 以新
  指纹重新授权 / 拒绝」三按钮 + 30s 超时默认拒绝；未知 kind/字段防御渲染
  （畸形 `fingerprintMismatch` 不 crash，回退普通 inject 审批）。
- **解析在 daemon 侧**（信 daemon 不信客户端）：对端真实 env PATH——
  Linux `/proc/<pid>/environ` / Windows PEB `ProcessParameters.Environment`
  / macOS `KERN_PROCARGS2`（验证后落地，失败 fail-closed）；比对序 = 路径
  → size → SHA-256（前两关免哈希）。
- **大文件性能**：内存指纹缓存 + 元信息失效（评估先 stat，一致即复用，
  O(stat)）+ 64 MiB 阈值（只影响预计算时机）+ size 快速失配门；缓存**不
  落盘**（防同用户投毒）。
- **边界**：防「冒充」（PATH 前置假程序 / 同名假程序 / 复现命令形态）；
  攻击者就地改写授权二进制本身 = 边界外（#15/#20 同源）；TOCTOU 接受 +
  文档声明。
