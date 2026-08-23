# 跨子系统访问规格（cross-subsystem：WSL CLI ↔ Windows 桌面守护实例）

- 状态：**已拍板**（decisions.md 补充拍板 #14，2026-08-22）——本文件为新增
  独立规格，未改动任何既有文档；实现时的老文档回填项见 §12。
- 关联：[ipc.md](ipc.md)（传输/会话/最小字段）·
  [authorization-gate.md](authorization-gate.md)（三层模型/启动者判定/绕过清单）
  · [decisions.md](decisions.md)（D8/D10 为本方案的安全基线，本方案不降低之）

## 1. 目标与非目标

### 目标

WSL 内的 **Linux 原生应用（含 agent 工具链）** 通过 `lk` 命令连接**同一台
Windows 主机**上的 LightKey 桌面应用（内置守护实例）：

1. 查看库中条目（`item.list` / `item.get`，需解锁会话）；
2. 请求授权获取密钥（`authz.evaluate` 三层模型，审批弹窗出现在 Windows GUI）；
3. 被批准的密钥值注入 **Linux 子进程**环境（`lk inject` 语义完整对齐）；
4. 全程可审计、默认拒绝语义不变。

### 非目标

- 跨主机访问（D8 远程审批通道仍为 P1 不做）；
- 免审批通道（任何跨子系统路径都不绕过第③层弹窗的可用性）；
- WSL1 支持（仅 WSL2；WSL1 无 interop 管道语义，明确不支持）。

## 2. 现状：为什么当前架构不支持

- 传输按平台二选一（ipc.md §2 / `lk-daemon/src/transport.rs`）：Linux 走
  Unix domain socket，Windows 走 named pipe。两条通道在 WSL/Windows 边界
  互不可达——Linux 进程打不开 `\\.\pipe\...`。
- WSL 内执行 Linux `lk` 会经 `ensure_daemon()` 拉起 **WSL 自己的守护实例**，
  指向 WSL 侧数据目录，与 Windows 桌面应用的库完全无关。
- 即使假想连通：WSL 进程的 PID 不在 Windows 进程表 → `starter.rs` 进程链
  回溯失败 → fail-closed 默认拒绝；规则 `projectDir` 的跨路径命名空间匹配
  语义未定义。

## 3. 候选通道取舍

| 候选 | 原理 | 结论 |
|------|------|------|
| A. interop 直调 `lk.exe` | WSL bash 直接运行 Windows `lk.exe`，客户端即真 Windows 进程 | ❌ 对本目标不成立：`lk.exe inject` 只能 spawn Windows 子进程，Linux 工具链拿不到注入值 |
| B. 守护进程 TCP 监听 | mirrored 模式双向 localhost；NAT 模式需非环回绑定 + 防火墙入站 | ❌ 依赖用户网络环境（.wslconfig / 防火墙 / VPN 差异大），且新增网络攻击面；**明确不采用** |
| C. npiperelay/socat | 外部工具经 interop stdio 转发 named pipe | ❌ 外部依赖 + 手工装配，不可产品化（但其原理验证了 stdio 中继可行性） |
| D. Hyper-V Socket / vsock | host↔WSL 专用通道，不经网络栈 | ❌ WSL2 上第三方使用未文档化、Rust 生态不成熟，且仍无法解决启动者取证 |
| **E. interop stdio 桥（本方案）** | Linux `lk` 把 JSON-RPC 帧经 interop 管道交给 `lk.exe bridge` 中继到 named pipe | ✅ **采用**。零网络依赖、零新增监听面、启动者取证保留 |

选 E 的决定性论据：**注入发生在客户端**是既有架构——`authz.evaluate` 把
批准的 env 集返回给客户端（`AuthzEvaluateResult.env`），由客户端 spawn 子进程
（`lk-cli/src/main.rs` `cmd_inject`）。因此只要 Linux `lk` 能完成同样的 RPC
往返，功能即完整对齐，包括给 Linux 子进程注入。

## 4. 本机实证记录（ThinkPad T14P，WSL2 Debian，2026-08）

以下均为真机实测结论，非文档推断：

| # | 环节 | 结果 | 证据 |
|---|------|------|------|
| 1 | interop 可用 | ✅ | `/proc/sys/fs/binfmt_misc/WSLInterop` 注册；Windows PATH 注入 `$PATH` |
| 2 | cwd 跨界继承 | ✅ | WSL 目录下 `cmd.exe /c cd` → `\\wsl.localhost\Debian\home\buji\...`；`/mnt/c/tmp` → `C:\tmp` |
| 3 | 管道字节完整性 | ✅ | raw-byte 模式 UTF-8 完美往返（多字节字符原样、`\n` 不变）；损坏仅发生于 cmd 文本模式（`more`），Rust stdio 为原始字节流，无此问题 |
| 4 | 启动者取证 | ✅ | interop 进程父链 Windows 侧完全可见：`powershell.exe → wsl.exe → wsl.exe → pwsh.exe → WindowsTerminal.exe → svchost.exe`（Win32_Process 实测）。Toolhelp 回溯不会 fail-closed |
| 5 | named pipe 可达 | ✅ | interop 进程 `NamedPipeClientStream` 连接活守护进程管道 `Connected=True` |
| 6 | HEAD 协议帧 | ✅ | 同款 `vault.status` 探测帧对仓库 HEAD 守护进程（UDS）秒回正确 JSON |
| 7 | 装机版兼容 | ❌ | 装机 `lk-app.exe` v0.1.0（2026-08-19 构建）对 HEAD 帧**静默关闭零响应**（含故意非法 method 也不回错误）——陈旧构建与 HEAD 协议不一致 |

由 #7 反哺的设计要求：**协议版本校验**（§7.3），防止新旧不匹配时静默失败。

## 5. 总体架构

```
┌─ WSL2 (Linux) ─────────────────┐           ┌─ Windows host ─────────────────────────┐
│ agent（Linux 原生，如 shell/CI） │           │                                          │
│   └─ lk（Linux ELF CLI）        │           │  lk.exe bridge（Windows PE，随桌面包安装） │
│       rpc() ── 行 JSON ──────▶  │─interop──▶│    stdin/stdout ↔ named pipe 原样中继     │
│       ←─ evaluate 返回 env 集    │  字节管道   │    │                                     │
│       spawn <linux-cmd>（注入）  │           │    ▼                                     │
│                                 │           │  lk-app.exe 内置守护实例（持钥）            │
│  会话令牌仅在 lk 进程内存         │           │    ├─ 启动者回溯：bridge→wsl.exe→…→终端    │
└─────────────────────────────────┘           │    ├─ cwd：bridge 继承 = 调用方项目目录 UNC │
                                              │    ├─ 三层模型 / 30s 弹窗 → GUI ✓          │
                                              │    └─ 审计（channel=wsl-bridge）✓          │
                                              └──────────────────────────────────────────┘
```

要点：

- **不新增任何监听面**：bridge 是按需拉起的短命客户端进程，不是服务；
- **用户边界不变**：interop 子进程以同一 Windows 用户令牌运行，named pipe 的
  「仅本用户」ACL（transport `UserOnlySa`）语义原样成立；
- **协议零变更**：行 JSON JSON-RPC、会话令牌、G1 三阶段审批、30s 超时默认拒绝
  全部照旧；服务端（lk-daemon / lk-app）**无需任何改动**。

## 6. 二进制与编译矩阵

| 二进制 | 编译目标 | 角色 | 交付 |
|---|---|---|---|
| `lk` | `x86_64-unknown-linux-gnu` | agent/用户在 WSL 内调用的入口 CLI | 新增 Linux 产物（CI ubuntu job 或 release 补齐） |
| `lk.exe` | `x86_64-pc-windows-msvc` | ① bridge 中继；② Windows 原生 CLI（现状不变） | release 流水线已有独立 CLI 产物；**需随桌面安装包落地**（当前装机目录缺失，见 §4#7 前科） |

同一 workspace，无代码分叉；平台差异收敛在 `transport.rs`（已有）与新增
`bridge` 子命令。

## 7. 详细设计

### 7.1 `lk.exe bridge` 子命令（Windows 侧中继）

- 形态：`lk.exe bridge --dir <数据目录>`（默认目录解析复用 `dirs::data_dir`）。
- 行为：从 stdin 逐行读 JSON-RPC 帧 → 连接 named pipe（复用
  `transport::connect/request`）→ 把响应行原样写到 stdout → 退出。
  一进程一请求（与现有 `transport::request()` 同构；首版不做长驻会话）。
- **字节纪律**：stdin/stdout 一律按原始字节读写（`std::io` 默认即如此），
  禁止任何文本模式转换（实证 #3：cmd 文本模式会损坏 UTF-8 与换行）。
- **阻塞语义**：`authz.evaluate` 的第③层会在服务端等待至多 30s
  （`approval_timeout_secs`），bridge 必须保持管道打开直到响应到达——
  单请求模式下天然成立（服务端每连接一线程阻塞式处理，实证架构支持）。
- 错误语义（stdout 单行 JSON-RPC error，退出码非 0）：
  - `bridge.no_daemon`：daemon.json 缺失或管道不可达；
  - `bridge.version_incompatible`：版本校验失败（§7.3）；
  - `bridge.io`：中继 I/O 失败。
- bridge **不做任何业务解析**（除版本校验外帧原样透传），决策权始终在
  守护进程——符合「安全流程硬编码在 Rust 守护进程侧」的既定边界。

### 7.2 Linux `lk` 传输抽象

- `rpc()` 增加后端选择：
  - `local`（现状）：UDS 直连 WSL 内守护实例，行为完全不变；
  - `bridge`：经 `lk.exe bridge` 中继到 Windows 守护实例。
- 配置解析优先级：显式环境变量 `LIGHTKEY_BRIDGE` > 平台默认：
  - **平台默认（裁定）**：检测到 WSL 环境 → 自动探测 bridge；非 WSL
    （Linux/macOS 原生）→ 本地 daemon（无跨子系统概念）；
  - WSL 探测条件：`/proc/sys/fs/binfmt_misc/WSLInterop` 存在，且可从
    `/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey/daemon.json` 读到端点
    并找到 lk.exe（已知安装位置清单，含 `%LOCALAPPDATA%\LightKey\`）；
  - 显式覆盖：`LIGHTKEY_BRIDGE=off`（强制本地，逃生口）/ `<路径>`（强制用
    该 exe 当中继，跳过探测；Windows 路径或 /mnt/c 形式均可）。
- **探测失败分型（防「空库错觉」——最危险的失败模式）**：

  | 情形 | 行为 |
  |---|---|
  | 在 WSL，Windows 侧装了 LightKey 但 bridge 连不上（lk.exe 缺失/管道不通/版本不兼容） | **明确报错**并提示检查安装，绝不静默回落本地 |
  | 在 WSL，Windows 侧没有 lightkey 数据目录 | 静默走本地 daemon（本来就没得连） |

- **目标可见性（auto 默认的安全补偿）**：每次经 bridge 执行命令向 stderr 打
  一行「→ 经 bridge 连接 Windows 桌面守护实例（版本 x.y）」；`lk status`
  输出含连接目标字段。杜绝「以为在操作本地、实际连着真库」的语义模糊。
- 端点发现：Windows 用户目录经 drvfs 定位（`/mnt/c/Users/*/AppData/...`），
  多用户/自定义盘时允许 `LIGHTKEY_BRIDGE_HOME` 显式指定数据目录。
- 会话令牌：仅存在于 `lk` 进程内存（D10 不变）；主密码在 WSL 终端交互输入
  （不回显），经桥传给 `vault.unlock`——与现状「主密码走本地 IPC」同级，
  不落盘、不进模型对话环境。

### 7.3 协议版本校验（实证 #7 的直接教训）

- `lk`/`lk.exe bridge` 首连时发 `vault.status`，校验响应 `version` 与自身
  `CARGO_PKG_VERSION` 的**主.次版本一致**（补丁号忽略）；
- 不一致 → `bridge.version_incompatible` 明确报错并提示重装桌面应用，
  **绝不静默降级**；
- `daemon.json` 增加 `version` 字段（可选，向后兼容：缺省时以 vault.status
  结果为准）。

### 7.4 projectDir 跨命名空间归一化（`lk-core::path_ns`）

- 新增 `path_ns::canonical_project_dir(raw) -> String`：
  - `\\wsl.localhost\<distro>\rest` / `\\wsl$\<distro>\rest` /
    `\\?\UNC\wsl.localhost\<distro>\rest` → 规范形 `wsl://<distro>/<rest>`；
  - `\\?\C:\...` 等 verbatim 前缀 → 剥离为常规 Windows 绝对路径（维持现状）；
  - 其余原样（canonicalize 语义不变）。
- **两侧同函数**：`rule.add` 入库时与授权门运行时 cwd 判定后，均先过此函数
  再做祖先匹配 → 匹配语义跨命名空间一致，不存在「两种写法各录一条规则」。
- `lk rule add`：传入以 `/` 开头且非现存 Windows 路径时，解析为
  `wsl://<默认发行版>/...` 并**回显解析结果要求确认**（默认发行版歧义显式化，
  防静默错配）；
- bridge 后端下显式 Windows 绝对路径（`X:\…` / `X:/…`）**直接采用**：跳过
  本地 fs canonicalize 与 wsl 解析守卫，原样送守护进程由 Windows 侧校验入库
  （非交互可直录 drvfs 规则）；
- bridge 后端下解析出的 POSIX 绝对路径同样折算并回显确认：drvfs 目录
  （`/mnt/<盘>/…`）→ Windows 绝对路径形态（与 interop bridge 进程继承的
  PEB cwd 同命名空间，精确匹配）；其余 → `wsl://<默认发行版>/...`。
- 归一化在**守护进程侧**执行（对 bridge 传来的 cwd 字符串），客户端自报值
  仍不被信任——判定依据始终是 bridge 进程的 PEB 真实 cwd（interop 继承）。

### 7.5 审计与弹窗展示

- `AuthzEvaluateParams.channel` 扩展枚举值：`cli` | `desktop` | **`wsl-bridge`**；
- 审计事件如实记录：starter = interop 中继链顶层（如 `wsl.exe`/终端进程），
  project_dir = UNC 归一化后的 `wsl://<distro>/...`，channel = `wsl-bridge`；
- 弹窗内容不变（启动者、项目目录、目标命令、key 名、倒计时），项目目录以
  `wsl://` 形态展示并标注「(WSL)」。

## 8. 安全分析

| 威胁 | 对策 |
|---|---|
| 跨用户访问 | interop 子进程继承同一 Windows 用户令牌；named pipe ACL（仅本用户）不变；WSL 默认用户即 Windows 用户 |
| 新增网络暴露 | 无——bridge 不监听任何端口/套接字 |
| 伪造启动者/项目目录 | 客户端自报字段仍不信任：PID 取自 `GetNamedPipeClientProcessId`，cwd 取自 bridge 进程 PEB（interop 继承的真实目录） |
| 绕过授权门 | 三层模型硬编码在守护进程，bridge 无决策权；fail-closed 语义（未知启动者/无 UI/超时）全部保留 |
| 密钥泄漏到对话环境 | 注入值仅经 `authz.evaluate` 响应到达 `lk` 进程并直接进子进程 env；审计/摘要永不明文（D11 不变） |
| 新旧版本静默失配 | §7.3 版本校验，明确报错 |
| interop 被禁用（企业策略） | 探测 `WSLInterop` 缺失 → 明确报错并提示；本方案唯一软依赖，可检测、可提示（对比网络方案的环境不可控） |

残余风险（接受并记录）：

- starter 顶层显示为 interop 中继链（非 WSL 内 bash/agent 进程名）；cwd 已
  足以定位项目，弹窗语义完整；
- 主密码经 interop 管道传输——与现状本地 IPC 同级（同用户、字节管道、不落盘）。

## 9. 实现清单

1. `lk-cli`（双平台）：`bridge` 子命令（§7.1）+ 版本校验（§7.3）；
2. `lk-cli`（Linux）：`rpc()` 传输抽象 + `LIGHTKEY_BRIDGE` 解析与探测（§7.2）；
3. `lk-core`：`path_ns` 模块 + 授权门/`rule.add` 接线（§7.4）；
4. `lk-core::ipc`：`channel` 枚举扩展 `wsl-bridge`（§7.5）；
5. `lk-daemon`：`daemon.json` 可选 `version` 字段；
6. release：Linux `lk` 产物 + 桌面包捆绑 `lk.exe` 到安装目录（修复 §4#7 缺口）；
7. 文档回填（拍板后）：见 §12。

## 10. 测试计划

- **单元**：`path_ns` 归一化（verbatim/UNC/wsl$ 别名/大小写/尾斜杠）；
  bridge 帧透传字节保真；版本校验三态；
- **E2E**：新增 `scripts/e2e_cross_subsystem.sh`（宿主需 WSL2 + 桌面包，
  CI 无 WSL 时跳过）：WSL `lk` unlock → item list → `authz.evaluate`
  弹窗批准 → Linux 子进程收到注入 env；审计含 `wsl-bridge` 事件；
- **安全专项**（authorization-gate.md §7 增补，拍板后回填）：
  - 伪造 `\\wsl.localhost` cwd 变体（大小写/`wsl$` 别名/尾缀）必须归一化后
    与规则一致匹配，不得绕过；
  - interop 禁用时必须显式失败（不回退到任何未授权路径）；
  - 版本不匹配必须拒绝服务（不静默）；
  - bridge 进程伪造/复用会话令牌：令牌仍随解锁轮换、进程内存独占。

## 11. 待拍板事项（已全部拍板，见 decisions.md 补充拍板 #14）

1. **bridge 默认开关**：✅ 裁定 auto 默认（修正版，2026-08-22 船长改定）：
   平台默认 = WSL 自动探测 bridge、非 WSL 本地 daemon；`LIGHTKEY_BRIDGE=off`
   为逃生口；探测失败按 §7.2 分型表处理（装了连不上→明确报错，没装→静默
   本地）；连接目标始终可见（stderr 提示 + `lk status` 字段）。
2. **`wsl://<distro>/...` 规范形格式**：✅ 裁定采用本规格建议形；
3. **版本校验口径**：✅ 裁定主.次一致（补丁号忽略，§7.3）；
4. **starter 展示文案**：✅ 裁定如实展示 interop 链 + `wsl://` 目录标注 (WSL)（§7.5）；
5. **里程碑归属**：✅ 裁定 M2.75（M3 浏览器填充之前）。

## 12. 拍板后的回填清单（本文件不执行）

- `decisions.md`：登记 §11 各项拍板结果；
- `ipc.md`：§2 传输增「跨子系统 stdio 桥」小节、§4 表格 channel 说明；
- `authorization-gate.md`：§3 启动者判定补 interop 链说明、§7 绕过清单增补
  （§10 所列四项）；
- `cli.md`：`LIGHTKEY_BRIDGE` 与 `lk bridge` 行为约束；
- `architecture.md` / `testing.md`：Linux CLI 产物与 E2E 说明。

## 附录 A：实证命令摘录（2026-08，本机）

```
# cwd 继承（WSL → UNC）
$ cd ~/firstmate/projects/lightkey && cmd.exe /c cd
'\\wsl.localhost\Debian\home\buji\firstmate\projects\lightkey'

# 父链可见（interop 进程 → … → 真实终端）
powershell.exe: Get-CimInstance Win32_Process …
  powershell.exe pid=7444 parent=17632 → wsl.exe → wsl.exe → pwsh.exe
  → WindowsTerminal.exe → svchost.exe

# 字节保真（raw 模式）
printf '{"note":"中文密钥✓"}\n' | powershell.exe -Command <raw in/out>
  → od 逐字节一致；cmd.exe /c more 则损坏（文本模式反例）

# HEAD 守护进程同帧秒回
{"jsonrpc":"2.0","id":1,"method":"vault.status","params":{}}
  → {"jsonrpc":"2.0","id":1,"result":{"syncWatermark":null,"unlocked":false,"version":"0.1.0"}}

# 装机版（2026-08-19 构建）同帧静默关闭 → 版本校验必要性实证
```
