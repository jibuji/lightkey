# 跨子系统通信测试 Runbook（WSL2 `lk` ↔ Windows 桌面守护实例）

- 读者：**执行测试的 Agent**（也可供人照做）。规格与设计依据见
  [cross-subsystem.md](cross-subsystem.md)（M2.75，补充拍板 #14）——链路拓扑、
  探测语义、`path_ns` 归一化等以该规格为准，本文只引用不复制；本文回答
  「装什么、怎么装、怎么测、怎么判」。
- 全程在 **WSL2 内操作**为主（标注「Windows 侧」的步骤在 PowerShell/CMD 执行）；
  所有命令可直接复制执行。
- 真机复测实战经验见
  [agents/win-host-cross-subsystem-retest.md](agents/win-host-cross-subsystem-retest.md)；
  最新实测结论（判定矩阵行 1：设计链路成立，2026-08-24）见
  [agents/win-host-cross-subsystem-retest-report-20260824.md](agents/win-host-cross-subsystem-retest-report-20260824.md)。

## 0. 前置事实表（先读再动手）

| 事实 | 内容 |
|---|---|
| 链路拓扑 | WSL 内 Linux `lk` → interop 字节管道 → Windows `lk.exe bridge`（短命中继，一进程一请求）→ named pipe → Windows 守护实例（持钥；两种形态见 §3）。bridge 不新增任何监听面，named pipe「仅本用户」ACL 不变 |
| 版本配对 | 两侧二进制**主.次版本必须一致**（补丁号忽略），不一致 → `bridge.version_incompatible` fail-closed，绝不静默降级（cross-subsystem.md §7.3）。**两侧必须来自同一 Release 或同一基线自建**，勿只换一侧 |
| Windows 数据目录 | `%APPDATA%\lightkey\`（= `C:\Users\<用户>\AppData\Roaming\lightkey\`；WSL 视角 `/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey/`）。端点文件 `daemon.json`（named pipe 名随机，端点一律从它读，不硬编码）；可选 `version` 字段。数据目录解析优先级 `--dir` > `LIGHTKEY_HOME` > 平台默认（`crates/lk-daemon/src/dirs.rs`） |
| 测试纪律 | fixture 密钥不入仓库（[testing.md](testing.md) §2）：测试密钥值运行时随机生成或环境变量注入；E2E 与手工探针操作**真实 Windows 库**但跑完自清（软删 + rule remove + lock）；假密钥值形如 `fake-not-a-real-key`；真实密钥/主密码/恢复码不进仓库、不进报告、不打进命令行参数 |

## 1. 环境判定（失败即停）

```bash
uname -r | grep -qi microsoft-standard-WSL2 && echo "WSL2 ✓"
[ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && echo "interop ✓"
```

完成判据：两行都打 ✓。任一失败即停止——WSL1 无 interop 管道语义，明确不支持
（cross-subsystem.md §1 非目标），换 WSL2 环境重测。

补充：企业策略禁用 interop 时，若 Windows 侧已装 LightKey，后续命令会得到
「WSLInterop 已被禁用…」明确报错（§9 排障表）——同样是环境问题，先修再测，
或经 `LIGHTKEY_BRIDGE=off` 回退本地语义。

## 2. 二进制获取（双路径）

### 路径 A：Release 产物（常规验证）

**同一 Release 的两个文件**（版本号必须相同，例以 v0.1.4 为例，换成目标 tag）：

| 文件 | 装到哪 | 角色 |
|---|---|---|
| `LightKey-<版>-windows-x86_64-setup.exe`（或 `.msi`） | Windows host | 桌面应用（内置守护实例 + 审批弹窗 GUI），**捆绑独立 `lk.exe` 到安装目录 `%LOCALAPPDATA%\LightKey\`** |
| `lk-cli-<版>-linux-x86_64` | WSL2 | Linux 入口 CLI |

```bash
gh release download v0.1.4 -R jibuji/lightkey \
  -p 'lk-cli-*-linux-x86_64' -p '*-setup.exe'
chmod +x lk-cli-*-linux-x86_64 && ./lk-cli-*-linux-x86_64 --version   # 记下版本
```

完成判据：两个文件在手且出自**同一 tag**；Release 构建的 `lk --version`
输出主.次与该 tag 一致。

### 路径 B：两侧自建（测新基线修复时必选）

测 #33（PEB cwd）/ #31（管道竞态）等新基线修复，必须**两侧分别自建且 ≥ 指定
commit**（如 #32 复测要求 main ≥ `b18b769`），**禁止拿旧安装的 lk.exe 当中继**
（同主.次的旧构建不会被 §7.3 版本校验拦截，会静默污染结论）：

```bash
# WSL 内（<DISTRO>）
git log --oneline -1            # 确认 ≥ 指定 commit
cargo build --release -p lk-cli # 产物 target/release/lk
```

```powershell
# Windows 侧 PowerShell（同一 checkout 经 /mnt/<盘> 访问即可，但必须分别构建）
cargo build --release -p lk-cli # 产物 target\release\lk.exe
```

完成判据：两侧产物存在可执行，`git log --oneline -1` 均 ≥ 指定 commit。

### 版本号判读红线（两条路径通用）

`lk --version` 显示的是编译进二进制的 workspace 版本（随 main 的 bump 演进，
本文写作时为 0.1.4；历史上曾长期是 0.1.0）——发布版本号由 Release 资产名/tag
承载（release.yml check-version 闸门，即 #34）。**不能拿自建产物的 `--version`
数字与 Release tag 比大小来判断新旧**；判断新旧看 commit 与行为探针（§5 判据 2
的 stderr 提示行是区分 bridge 后端有无的标志）。

## 3. Windows 侧守护形态（二选一）

| | 形态 A：桌面应用 | 形态 B：纯 CLI daemon |
|---|---|---|
| 就位方式 | 启动 LightKey（托盘常驻 = 守护在线） | Windows 侧跑**任一本地 `lk.exe` 命令**自动拉起，并写 `%APPDATA%\lightkey\daemon.json`（先跑一次 `.\lk.exe status` 确认生成；自建产物或安装目录内那份均可） |
| 审批弹窗 | **只有它有**审批弹窗 GUI | 无弹窗：未命中规则的交互审批请求以 `no_ui`（无审批界面）拒绝，属预期而非缺陷 |
| 库初始化 | 首启四步向导（设主密码 → 抄恢复码 → 解锁），**需真人在 Windows GUI 操作，Agent 无法代点** | `.\lk.exe init` 设测试主密码（≥8 位），一次性恢复码抄后可丢弃 |
| 适用场景 | 第③层弹窗层验证（交互模式 E2E、§7.1 手动深测） | **无人值守回归首选**（配 E2E `--auto-approve`，第②层白名单免弹窗，降低对审批 UI 的依赖） |

完成判据（WSL 内验证，任一形态都过）：

```bash
cat /mnt/c/Users/*/AppData/Roaming/lightkey/daemon.json    # 端点（+ 可选 version 字段）
ls /mnt/c/Users/*/AppData/Local/LightKey/lk.exe            # setup.exe 装机：捆绑的中继就位
ls '/mnt/c/Program Files/LightKey/lk.exe'                  # .msi 装机为 per-machine 目录（两条 ls 二选一存在即可；路径 B 自建时改为查构建产物路径）
```

## 4. 连接控制：`LIGHTKEY_BRIDGE` / `LIGHTKEY_BRIDGE_HOME`

Linux `lk` 的 RPC 出口二选一：local（UDS 直连 WSL 本地守护实例）/ bridge（经
`lk.exe` 中继）。选择优先级（cross-subsystem.md §7.2）：

| 设置 | 行为 |
|---|---|
| `LIGHTKEY_BRIDGE=off` | 强制本地（逃生口；即使装了 LightKey 也走 WSL 自己的库） |
| `LIGHTKEY_BRIDGE=<路径>` | 强制以该 exe 作中继，跳过探测；Windows `C:\...` 或 `/mnt/c/...` 形式均可 |
| 未设 + 非 WSL | 本地 daemon（无跨子系统概念） |
| 未设 + WSL | 自动探测：找到 `/mnt/<盘>/Users/*/AppData/Roaming/lightkey/daemon.json`（=「装了」）→ 在已知安装位置找 lk.exe |

已知安装位置：`%LOCALAPPDATA%\LightKey\`（桌面包捆绑落地处）、
`%LOCALAPPDATA%\Programs\LightKey\`、`%APPDATA%\LightKey\`（CLI 探测清单
`KNOWN_EXE_DIRS`）；E2E 脚本另查 `C:\Program Files\LightKey\` 作 per-machine 兜底。

**探测失败分型（防「空库错觉」——最危险的失败模式）**：

- 在 WSL 且装了 LightKey 但 bridge 连不上（lk.exe 缺失 / interop 禁用 /
  显式路径不可达）→ **明确报错，绝不静默回落本地**；
- 在 WSL 且没装（无 lightkey 数据目录）→ 静默走本地 daemon（本来就没得连）。

`LIGHTKEY_BRIDGE_HOME=<数据目录>`：多用户 / 非默认盘符时显式指定 Windows 数据
目录（`/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey` 或 `D:\MyData\lightkey`
形式均可）。注意：显式设置即视为「装了」，即使附近找不到 lk.exe 也是 fail-closed
明确报错，不会静默回落本地。

另一处隐性依赖：会话令牌由 Windows 侧守护实例写在其数据目录、`lk` 经
drvfs 回读；`LIGHTKEY_BRIDGE=<路径>` 显式指定中继而数据目录既未用本变量给出、
默认位置也扫不到 `daemon.json` 时，只有解锁类命令可用——unlock 成功后其余命令
会报「库未解锁或会话已失效」。此时补上 `LIGHTKEY_BRIDGE_HOME` 即可（§9）。

探测分型自检（可选，每条都是断言）：

| 操作 | 期望 |
|---|---|
| `LIGHTKEY_BRIDGE=off "$LK" status` | 无「经 bridge」提示行（本地语义）；本地守护实例未在运行则被自动拉起（现状 `ensure_daemon` 行为）——输出都不是 bridge 报错 |
| `LIGHTKEY_BRIDGE=/nonexistent "$LK" status` | 明确报错（强制中继不可达不许回落本地） |
| Windows 侧守护实例退出后 `"$LK" status` | 报 `bridge.no_daemon` 类错误并提示启动守护实例（§9） |

**纪律：测新构建时必须显式设置**：

```bash
export LIGHTKEY_BRIDGE=/mnt/<盘>/<repo>/target/release/lk.exe   # 路径 B；路径 A 用安装位置路径
```

否则自动探测可能命中 `%LOCALAPPDATA%\LightKey\` 下旧版 lk.exe——同主.次的旧
构建能通过版本校验，实测结论被静默污染。

## 5. 连通性探测

```bash
"$LK" status        # $LK = Linux lk 二进制；已 export LIGHTKEY_BRIDGE
```

完成判据（三条全中才算通）：

1. exit 0；
2. **stderr 含提示行「→ 经 bridge 连接 Windows 桌面守护实例（版本 …）」**
   （目标可见性拍板；括号内为对端完整版本号，如实测「（版本 0.1.4）」。也是
   区分旧版二进制的标志——旧版静默走本地无此行）；
3. stdout 版本与本地二进制主.次一致：默认文本行
   `状态: … | 版本: x.y.z | 连接: Windows 桌面守护实例（经 bridge） | …`；
   机器可读断言用 `"$LK" --json status`（含 `"target":"bridge"` 与 `"version"`
   字段，主.次要一致）。

报错对照 §9 排障表。通了进入 §6。

## 6. E2E 主测试（[../scripts/e2e_cross_subsystem.sh](../scripts/e2e_cross_subsystem.sh)）

用法（仓库根目录执行）：

```bash
bash scripts/e2e_cross_subsystem.sh [lk-binary-path] [--auto-approve]
```

- 第一个位置参数 = Linux lk 二进制路径（默认 `target/debug/lk`，显式传 release
  路径）；`-h` 打印脚本头说明；多余位置参数报错 exit 2。
- 脚本尊重预先 export 的 `LIGHTKEY_BRIDGE`（强制中继）与 `LIGHTKEY_BRIDGE_HOME`
  （定位数据目录）；未设时自行扫描已知位置并在 `== 0.` 步打印选定值。

**模式 A：交互批准（默认，需人在 Windows 屏幕前 + 桌面应用形态）**

```bash
bash scripts/e2e_cross_subsystem.sh ./lk-cli-0.1.4-linux-x86_64
# 先提示输入 Windows 侧主密码（read -s 不回显）；inject 弹窗出现后 30s 内点「批准」
```

**模式 B：无人值守（Agent 自主回归首选，无弹窗）**

```bash
export LK_CROSS_MASTER_PW='<Windows侧库的主密码>'
export LIGHTKEY_BRIDGE=/mnt/<盘>/<repo>/target/release/lk.exe   # 测自建时必设
bash scripts/e2e_cross_subsystem.sh target/release/lk --auto-approve
unset LK_CROSS_MASTER_PW
```

`--auto-approve` 硬性要求 `LK_CROSS_MASTER_PW`（缺失即报错 exit 2）；免弹窗
靠先 `rule add` 白名单命中（第②层），其余断言与模式 A 完全一致。

脚本自动做什么（输出步骤编号 `== N.` 与下表对应）：

| 步骤 | 自动动作与断言 |
|---|---|
| == 0. 前置就绪 == | 打印探测到的数据目录与中继路径，export `LIGHTKEY_BRIDGE` |
| == 1. 连接目标可见性 == | status stderr 含「经 bridge」提示行 |
| == 2. unlock == | 主密码经 stdin 注入 `lk unlock --stdin`，走 bridge；失败时提示 `bridge.no_daemon` → 先启动守护实例重试 |
| == 3. item list == | 读 Windows 真实库（list 为空属正常，不算失败） |
| == 4. 注入测试密钥 == | `item add secret LK_E2E_CROSS`，值运行时随机生成（真实库，跑完即删） |
| == 5. authz.evaluate → 注入 == | 模式 B：`rule add wsl://$WSL_DISTRO_NAME<临时项目目录> "sh *"` 白名单命中免弹窗（显式 `wsl://` 规范形，非交互下折算形会被拒）；模式 A：提示后弹窗人工批准。随后 inject 断言：exit 0、子进程 env 值与注入值一致、lk 自身 stderr 不泄漏密钥值 |
| == 6. 审计 == | `audit --json` 含 `channel=wsl-bridge` 事件且不含密钥值 |
| == 7. 清理 == | rule remove（仅模式 B 有规则）、`item delete`（软删 `[deleted]` 断言）、lock |

末行输出 `跨子系统 E2E（auto-approve）：N 通过 / M 失败`（交互模式为
`跨子系统 E2E（人工批准）：N 通过 / M 失败`）；完成判据：exit 0 且 M=0。
auto 模式还要求 `$WSL_DISTRO_NAME` 已设（WSL 正常预置）。

**SKIP 门（前置不满足 → 打印 `SKIP: <原因>` 并 exit 0）**。六条文案归四类：

| 类别 | SKIP 文案 | 处置 |
|---|---|---|
| ① 环境 ×2 | `宿主不是 WSL2（uname -r=…）` ／ `WSLInterop 未启用（/proc/sys/fs/binfmt_misc/WSLInterop 不存在）` | 修环境（§1），不可绕过 |
| ② 数据目录 | `Windows 侧未安装 LightKey 桌面应用（未找到 AppData/Roaming/lightkey/daemon.json；可用 LIGHTKEY_BRIDGE_HOME 指定）` | 先按 §3 让守护实例就位一次；非默认位置用 `LIGHTKEY_BRIDGE_HOME` |
| ③ 中继 | `未找到 Windows 侧 lk.exe（已查 %LOCALAPPDATA%\LightKey\ 与 Program Files；可用 LIGHTKEY_BRIDGE=<路径> 指定）` | 装 setup.exe 或显式指定自建产物路径 |
| ④ Linux 二进制 ×2 | `lk 二进制不可执行：<路径>（先 cargo build -p lk-cli）` ／ `Linux lk 尚未实现 bridge 后端（status 无「经 bridge」提示，M2.75 待合入）` | 构建或更换为含 bridge 后端的二进制 |

**「SKIP ≠ 链路失败」纪律**：SKIP 是前置检测干净退出（CI 无 WSL 必须 exit 0），
不代表桥本身坏；按上表补齐后重跑，**不要绕过 SKIP 改测本地**。只有前置全过后
输出的 ✗ 行才计入链路判定。

## 7. 手动深测（可选：弹窗层与规则语义定点验证）

前提：`$LK` 与 `LIGHTKEY_BRIDGE` 已按 §5 就绪；测试密钥用假值
（如 `fake-probe-value`），探针完清理（`rule remove` + `item delete` + `lock`，
`rule list | grep probe` 应无残留）。

### 7.1 第③层弹窗验证（需桌面应用形态）

```bash
"$LK" item add secret --name LK_PROBE_FAKE --value fake-probe-value --purpose test
```

在**未命中规则**的目录发起注入（若已按 §7.2 给 `~/proj` 录了规则，就从 `/tmp`
等其他目录发起——命中规则的目录会被第②层白名单直接放行，不弹窗）：

```bash
cd /tmp && "$LK" inject --keys LK_PROBE_FAKE -- sh -c 'echo -n "$LK_PROBE_FAKE"'
```

观察点（每条都是断言）：

- Windows 屏幕弹出审批窗：显示启动者（interop 中继链顶层）、项目目录
  （`wsl://<发行版>/...` 并标注 (WSL)）、目标命令、key 名、30s 倒计时；
- 点「批准」→ 子进程 echo 出注入值；lk 自身 stderr 无明文；
- 点「拒绝」或不理会超时 → 子进程拿不到值（fail-closed 默认拒绝，拒绝原因
  `rejected` / `timeout`）；
- 收尾：`"$LK" item list` 找 id 后 `"$LK" item delete <id>`。本步**不建规则**
  （弹窗层恰恰依赖未命中）；若此前做过 §7.2/§7.3 探针，按 §7 开头要求
  `rule remove` 并确认 `rule list | grep probe` 无残留。

### 7.2 规则 projectDir 必须显式规范形（cross-subsystem.md §7.4）

正向对照探针 A（命中目录 → 应放行）：

- WSL 原生目录：**必须显式 `wsl://<发行版>/…` 规范形**入库：
  `"$LK" rule add "wsl://${WSL_DISTRO_NAME}$HOME/proj" "sh *" --name probe-a LK_PROBE_FAKE`，
  随后在 `~/proj` 内 inject 应成功且审计（§8）channel 为 `wsl-bridge`。
  非交互环境（脚本/管道）下按默认发行版折算的形态会被**明确拒绝**并提示改用
  显式规范形重试（防脚本静默错配）；交互 TTY 会回显折算结果要求 y/N 确认——
  两种场景都建议直接写规范形。
- drvfs 项目目录（项目落在 `/mnt/<盘>/…`，如 NTFS 上的 checkout）：应配
  **Windows 盘符形态规则**——bridge 后端下 `"$LK" rule add 'X:\path' ...`
  直通入库（非交互可直录）。**不要对 drvfs 目录用 `wsl://` 形态**：interop
  继承转写后的 cwd 是 `C:\...` 盘符形态而非 `wsl://` 形态，命名空间不同匹配不上。

### 7.3 探针 B 判别法（inject 被拒时先做这一步）

在**不命中规则**的目录重跑 inject，读拒绝原因：

```bash
cd /tmp && "$LK" inject --keys LK_PROBE_FAKE -- sh -c true
# stderr: lk inject: 已拒绝（<原因文案>）
```

判定关键（指挥棒，stderr 必须原文留档）：

- 原因 = `无法确定工作目录`（协议面 `no_cwd`）→ daemon 从 bridge 进程 PEB
  **读不到** cwd → 链路取证层问题（历史故障点，#33 已修；复现即上报）；
- 原因 = 其他（`no_ui` / `timeout` / `rejected` 等）→ **cwd 读到了**，只是
  目录不匹配 → PEB 取证在 interop 下可用，问题只剩匹配层（回 §7.2 核对规范形
  与命名空间，逐项比对 `rule list` 入库 project_dir 与理论规范形）。

2026-08-24 真机结论：探针 B 得 `no_ui` ≠ `no_cwd`，PEB cwd 可读，判定矩阵
行 1（设计链路成立），详见
[agents/win-host-cross-subsystem-retest-report-20260824.md](agents/win-host-cross-subsystem-retest-report-20260824.md)。

### 7.4 GUI 弹窗存在性探测（Agent 可执行；30s 倒计时内）

§7.1 的观察点默认靠人眼；本节给出**客观探针**，让执行测试的 Agent 在 30s
倒计时窗口内自行判定「Windows 屏幕上审批弹窗确实出现了」。人工观察仍保留为
兜底（探针异常时以人眼为准）。

**代码取证（探针依据，禁止改写这些字符串）**：

- 审批弹窗不是独立 Tauri 窗口——应用只有一个主窗口（`crates/lk-app/`
  `tauri.conf.json` 的 `app.windows[0]`：`"title": "LightKey"`），审批对话框是
  该窗口 webview 内的模态层（`frontend/src/plugins/approval.tsx`：
  `<div className="modal-overlay" role="dialog" aria-modal="true"
  aria-label="授权请求审批">` + 标题 `授权请求 · {starter}`）。
- 因此进程级标题枚举只能证明**必要条件**（LightKey 桌面进程活着、有可见
  主窗口）；判定「弹窗出现」须用 **Windows UI Automation（UIA）读 WebView2
  无障碍树**找上述 aria 文案。Tauri 主窗口 label 为 `main`
  （`crates/lk-app/src/lib.rs` 托盘代码 `get_webview_window("main")`）。

前置条件：LightKey 主窗口处于**显示状态**（托盘关闭只是隐藏窗口——若被隐藏，
先从托盘菜单点「显示主窗口」，否则 UIA 树里探不到弹窗内容）。

探针脚本（WSL 内直接复制执行；经 interop 调 powershell.exe）：

```bash
cat > /tmp/lk-popup-probe.ps1 <<'EOF'
Add-Type -AssemblyName UIAutomationClient
# 必要条件①：LightKey 进程存活且持可见主窗口
$proc = Get-Process | Where-Object { $_.MainWindowTitle -eq 'LightKey' } | Select-Object -First 1
if (-not $proc) { Write-Output 'NECESSARY-FAIL: 无标题为 LightKey 的可见主窗口'; exit 1 }
Write-Output ("NECESSARY-OK: pid={0} proc={1}" -f $proc.Id, $proc.ProcessName)
# 判定性断言②：UIA 全桌面搜审批弹窗的 aria 文案
$root = [System.Windows.Automation.AutomationElement]::RootElement
$cond = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::NameProperty, '授权请求审批')
$hit = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
if ($hit) {
  $w = $hit.Current.FrameworkId
  Write-Output "POPUP-FOUND: 授权请求审批 (framework=$w)"
  exit 0
} else {
  Write-Output 'POPUP-NOT-FOUND'
  exit 2
}
EOF
# 关键：给脚本加 UTF-8 BOM——Windows PowerShell 5.1 对无 BOM 文件按 ANSI 解码，
# 中文字符串「授权请求审批」会乱码导致永远 POPUP-NOT-FOUND（假阴性）
printf '\xef\xbb\xbf' | cat - /tmp/lk-popup-probe.ps1 > /tmp/lk-popup-probe.bom.ps1 \
  && mv /tmp/lk-popup-probe.bom.ps1 /tmp/lk-popup-probe.ps1
```

**正向断言（弹窗出现）**——两个终端配合，30s 倒计时内完成：

```bash
# 终端 1（发起，阻塞等待裁决）：
cd /tmp && "$LK" inject --keys LK_PROBE_FAKE -- sh -c 'echo -n "$LK_PROBE_FAKE"'
# 终端 2（立即跑探针，倒计时间内多跑几次直到 POPUP-FOUND 或 inject 返回）：
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w /tmp/lk-popup-probe.ps1)"
```

完成判据（两条都要）：

1. `NECESSARY-OK: pid=<N> proc=LightKey`（进程名应为 `LightKey`；
   若为 `lk` 则当前是 CLI daemon 形态，见反向说明）；
2. `POPUP-FOUND: 授权请求审批 …`——即屏幕上确有审批弹窗。探到后**仍需真人在
   Windows 屏幕上点批准/拒绝完成闭环**（Agent 无法代点；Esc = 拒绝）。

**反向断言（免弹窗路径探不到）**：

```bash
# 场景 A：纯 CLI daemon 形态（先退出桌面应用，Windows 侧跑任一 lk.exe 命令拉起 CLI daemon）
cd /tmp && "$LK" inject --keys LK_PROBE_FAKE -- sh -c true   # 立即被拒（no_ui）
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$(wslpath -w /tmp/lk-popup-probe.ps1)"
# 期望：NECESSARY-FAIL 或 NECESSARY-OK(proc=lk) + POPUP-NOT-FOUND —— 印证 §3 表格「形态 B 无弹窗」语义

# 场景 B：规则命中免弹窗（第②层白名单；--auto-approve E2E 即此路径）
# 按 §7.2 给当前目录录规则后 inject 成功、全程无弹窗 → 探针同样应输出 POPUP-NOT-FOUND
```

两个场景都探到 `POPUP-FOUND` 才算失败——那是免弹窗路径漏弹窗的证据，上报。

兜底：UIA 探针受 WebView2 渲染进程无障碍树暴露时机影响（个别环境首次触发
可能延迟数百毫秒），`inject` 尚未返回前可间隔 1s 重试至多 5 次；仍
`POPUP-NOT-FOUND` 而 `inject` 又在阻塞等裁决时，转人工看屏确认并留档差异。

## 8. 审计断言

```bash
SECRET_VALUE='fake-probe-value'      # §7 探针注入的假值（E2E 则为其运行时随机生成的值）
AUDIT_JSON="$("$LK" audit --json)"   # 需库处于解锁态；只要最近片段可改 --json --tail 10
printf '%s' "$AUDIT_JSON" | grep -q '"wsl-bridge"' \
  && echo "✓ 断言 1：审计含 channel=wsl-bridge 事件" || echo "✗ 断言 1 未命中"
printf '%s' "$AUDIT_JSON" | grep -q "$SECRET_VALUE" \
  && echo "✗ 断言 2 失败：审计泄漏明文密钥值" || echo "✓ 断言 2：审计无明文密钥值"
```

完成判据：

1. 相关操作后的审计含 `"channel": "wsl-bridge"` 事件（starter = interop 中继链
   顶层，project_dir = `wsl://<发行版>/...` 规范形）；
2. 审计全文不含任何明文密钥值（grep 注入值零命中）；
3. 可选加固：`"$LK" audit --verify` 校验 HMAC 链；也可直接读 Windows 侧
   `%APPDATA%\lightkey\audit.log`（`lk audit` 需库处于解锁态；直接读文件分析亦可）。

## 9. 排障速查表

| 症状 | 原因 → 处置 |
|---|---|
| `SKIP: 宿主不是 WSL2（uname -r=…）` | 环境门① → 换 WSL2（WSL1 明确不支持） |
| `SKIP: WSLInterop 未启用（…不存在）` | 环境门① → `/etc/wsl.conf` 启用 interop 后重启 WSL |
| `SKIP: Windows 侧未安装 LightKey 桌面应用（未找到 AppData/Roaming/lightkey/daemon.json…）` | 门②：守护实例从未就位 → 按 §3 就位一次；非默认位置 → `export LIGHTKEY_BRIDGE_HOME=/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey` |
| `SKIP: 未找到 Windows 侧 lk.exe（已查 %LOCALAPPDATA%\LightKey\ 与 Program Files…）` | 门③ → 装 setup.exe，或 `export LIGHTKEY_BRIDGE=<自建 lk.exe 路径>` |
| `SKIP: lk 二进制不可执行：<路径>…` | 门④ → 构建 Linux 侧 `cargo build --release -p lk-cli` 或传对路径 |
| `SKIP: Linux lk 尚未实现 bridge 后端（status 无「经 bridge」提示…）` | 门④ → 二进制是 M2.75 之前旧版，重建/换新 Release |
| 「检测到 Windows 侧已安装 LightKey…WSLInterop 已被禁用」 | 装了但 interop 被禁（fail-closed 分型）→ 启用 interop，或 `LIGHTKEY_BRIDGE=off` 回退本地语义 |
| 「检测到 Windows 侧已安装 LightKey…已知安装位置均未找到 lk.exe」 | 有数据目录没中继 → 重装桌面包，或 `LIGHTKEY_BRIDGE` 显式指定 |
| `bridge.no_daemon` | daemon.json 缺失或 named pipe 不可达（守护实例没在运行）→ 启动桌面应用（托盘常驻），或在 Windows 侧跑任一 `lk.exe` 命令拉起 CLI daemon，再重试 |
| `bridge.version_incompatible` | 两侧主.次不一致，或对端陈旧构建（对探测帧静默关闭也归此类）→ **两侧同时**换同一 Release / 同基线重建；勿只换一侧 |
| `bridge.io` | 中继 I/O 失败或帧非 UTF-8 → 单发重试；持续复现留完整 stderr 上报（#31 已根治传输竞态，复发即证据） |
| unlock 失败 | 主密码不对：这是 **Windows 侧库的密码 ≠ WSL 本地库密码**；并确认没被 `LIGHTKEY_BRIDGE=off` 误切到本地库上操作 |
| unlock 成功但后续命令报「库未解锁或会话已失效」 | `LIGHTKEY_BRIDGE` 显式指定了中继但数据目录没定位到，会话令牌读不回（§4）→ `export LIGHTKEY_BRIDGE_HOME=<Windows 数据目录>` 后重试 |
| 弹窗超时（拒绝原因 `timeout`） | 30s 倒计时内没人点 → 重跑该命令并守在 Windows 屏幕前，或改 §6 模式 B |
| 拒绝原因 `no_ui` | 纯 CLI daemon 无审批界面，未命中规则的交互审批被拒——**属预期**；要验证弹窗须切换到桌面应用形态（§3） |
| §7.4 探针 `POPUP-NOT-FOUND`（但人眼可见弹窗） | UIA 树未暴露：主窗口被隐藏到托盘（先托盘「显示主窗口」）、WebView2 无障碍树延迟（1s 间隔重试至多 5 次）、或窗口标题版本差异（探针字符串以本节代码取证为准）→ 转人工观察兜底 |
| status 没有「经 bridge」提示（以为在测桥实际在测本地） | 二进制旧 / `LIGHTKEY_BRIDGE=off` / 未设且没装 → 换新二进制并显式 export `LIGHTKEY_BRIDGE`（§4 纪律） |
| `多余参数：<arg>`（exit 2）／`--auto-approve 需要 LK_CROSS_MASTER_PW`（exit 2） | 用法错误 → 只传一个位置参数 + 可选 `--auto-approve`；无人值守先 export 主密码 |
