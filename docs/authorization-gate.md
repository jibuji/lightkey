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

- **agent 只能看到被授权的 key 名**：规则白名单决定注入集合；未授权 key 名
  对 agent 不可见（包括规则之外存在哪些 key）。
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
- 结果供审计 `starter` 字段与规则匹配使用。

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
- **密钥只注入被批准具名命令的进程环境**：
  - 注入的是子进程环境变量，**绝不进入模型对话环境**（agent 无法通过
    stdout/日志拿回未授权值；agent 拿到的只有「已注入/已拒绝」）。
  - env 变量名（key 名）对 agent 可见，值不可见——除非该 key 已授权。
- 示例：`NPM_TOKEN=... lk inject --keys NPM_TOKEN -- npm publish` 的等价效果（但经授权门裁决）。
- 内建脱敏：注入值在审计/命令摘要中永不明文（见 [audit.md](audit.md) §2）。

## 6. 审批通道抽象（D8）

- 审批通道 = 接口（trait）`ApprovalChannel`（本地/远程可切换）；两阶段接口
  对应守护进程的 G1 三阶段编排（`authz.evaluate` 锁内登记 → 锁外等待 → 重取锁
  收尾）：
  - `available()` — 是否有界面可能响应审批（桌面壳已订阅推送连接）；
    `false` → fail-closed 立即拒绝（不登记、不阻塞）。
  - `open(req, expires_at)` — 登记待审批 + 广播 `authz.request`（命令锁内、
    非阻塞）。
  - `await_decision(request_id, expires_at)` — 命令锁外等待决策，返回
    `Allowed` / `Denied` / `Timeout`（到期默认拒绝）。
- **本地通道**（V1）：桌面弹窗/系统通知，30s 超时默认拒绝。
- **远程通道**（未来，P1 不做）：远程审批中继 = 未来服务端付费点；本阶段
  只留接口与类型，不实现。
- 弹窗内容（最小展示）：启动者、项目目录、目标命令、请求的 key 名、
  倒计时；不展示密钥值。

## 7. 安全约束与测试要点

- fail-closed：启动者未知 / 规则库损坏 / 守护进程无界面 → 一律拒绝。
- **已知边界（待拍板，issue #65）**：三层门当前仅约束 `authz.evaluate`
  （即 `lk inject`）通道；`item.list` / `item.get` 等 IPC 方法持有效
  会话令牌即可读全库明文，不经规则匹配与审批。即本门对「自觉走 inject
  的 agent」是流程约束，对**不合作的同用户进程**（解锁窗口内直接调
  `item.*`）无效——事后归因依赖审计真实 starter（已落，#66）；按调用方
  区分能力面 / 解锁+审批一体化（#67）等收紧方案待决策后落规格。
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
