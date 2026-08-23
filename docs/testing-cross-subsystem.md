# 跨子系统通信测试 Runbook（WSL2 `lk` ↔ Windows 桌面守护实例）

- 读者：**执行测试的 Agent**（也可供人照做）。规格与设计依据见
  [cross-subsystem.md](cross-subsystem.md)；本文只回答「装什么、怎么装、怎么测」。
- 全程在 **WSL2 内操作**（除标注「Windows 侧」的步骤）；所有命令可直接复制执行。

## 0. 前置事实（先读再动手）

| 事实 | 内容 |
|---|---|
| 拓扑 | WSL 内 Linux `lk` → interop 字节管道 → Windows `lk.exe bridge` → named pipe → `lk-app.exe` 内置守护实例（持钥） |
| 版本配对 | 两侧二进制**主.次版本必须一致**，否则 `bridge.version_incompatible` fail-closed——**两边必须下载同一个 Release** |
| 守护实例归属 | 守护进程由桌面应用进程内持有：**LightKey 桌面应用必须在运行**（托盘常驻），没有「独立启动 daemon」一说 |
| Windows 数据目录 | `%APPDATA%\lightkey\`（WSL 视角：`/mnt/c/Users/<用户>/AppData/Roaming/lightkey/`，端点见其中 `daemon.json`） |
| `lk.exe` 安装位置 | `%LOCALAPPDATA%\LightKey\` 或 `%LOCALAPPDATA%\Programs\LightKey\` 或 `C:\Program Files\LightKey\` |
| 测试纪律 | 密码/密钥值运行时生成或环境变量注入，不进仓库；E2E 用真实库但跑完自清（软删 + 锁定） |

## 1. 环境判定

```bash
uname -r | grep -qi microsoft-standard-WSL2 && echo "WSL2 ✓"
[ -e /proc/sys/fs/binfmt_misc/WSLInterop ] && echo "interop ✓"
```

完成判据：两行都打 ✓。任一失败即停止——WSL1 无 interop 管道语义，明确不支持
（cross-subsystem.md §1 非目标），换 WSL2 环境重测。

## 2. 下载 Release 产物（同一 Release、两个文件）

以 v0.1.3 为例（最新版把 `v0.1.3` 换成目标 tag 或用 `latest`）：

| 文件 | 装到哪 | 角色 |
|---|---|---|
| `LightKey-<版>-windows-x86_64-setup.exe` | Windows host | 桌面应用（内置守护实例 + 审批弹窗 GUI），**捆绑 `lk.exe` 到安装目录** |
| `lk-cli-<版>-linux-x86_64` | WSL2 | Linux 入口 CLI |

```bash
# WSL 内直接取两个文件（下载到当前目录）
gh release download v0.1.3 -R jibuji/lightkey \
  -p 'lk-cli-*-linux-x86_64' -p '*-setup.exe'
chmod +x lk-cli-*-linux-x86_64 && ./lk-cli-*-linux-x86_64 --version   # 记下版本
```

无 `gh` 时用浏览器从 `https://github.com/jibuji/lightkey/releases/tag/v0.1.3` 下载。
完成判据：两个文件在手，`--version` 输出的主.次与所下 Release 版本一致。

## 3. Windows 侧安装并启动

1. 双击 `*-setup.exe`（静默装可试 `/S`；MSI 用 `msiexec /i <msi> /qn`）。未签名，
   SmartScreen 警告属预期，选「仍要运行」。默认装到 `%LOCALAPPDATA%\LightKey\`。
2. 启动 LightKey：
   - **已有库** → 出解锁页，解锁后进主界面；
   - **首次安装** → 四步初始化向导（设主密码 ≥8 位 → 抄恢复码（仅此一次）→ 解锁）。
     **向导需真人在 Windows GUI 操作**，Agent 无法代点；无人值守场景请先用已有库。
3. 保持应用运行（托盘常驻 = 守护实例在线）。

WSL 内验证装机结果（完成判据：三条都能看到）：

```bash
ls "/mnt/c/Users/*/AppData/Local/LightKey/lk.exe"            # bridge 中继就位
cat /mnt/c/Users/*/AppData/Roaming/lightkey/daemon.json      # 端点 + version 字段
```

## 4. 连通性探测

```bash
LK=./lk-cli-0.1.3-linux-x86_64
"$LK" status
```

完成判据（三条全中才算通）：

1. exit 0；
2. **stderr 有「→ 经 bridge 连接 Windows 桌面守护实例」提示行**（目标可见性，
   也是区分旧版二进制的标志）；
3. stdout JSON 含连接目标/version 字段且 `version` 主.次与本机 `$LK` 一致。

报错对照下方 §7 排障表。通了就进入 §5。

## 5. E2E 脚本（主测试，二选一模式）

仓库根目录执行，第一个参数指向刚下载的 lk 二进制：

**模式 A：交互批准（默认，需人在 Windows 屏幕前）**

```bash
bash scripts/e2e_cross_subsystem.sh ./lk-cli-0.1.3-linux-x86_64
# 提示输入 Windows 侧主密码（不回显）；inject 触发弹窗时 30s 内点「批准」
```

**模式 B：无人值守（Agent 自主回归首选，无弹窗）**

```bash
export LK_CROSS_MASTER_PW='<Windows侧库的主密码>'
bash scripts/e2e_cross_subsystem.sh ./lk-cli-0.1.3-linux-x86_64 --auto-approve
unset LK_CROSS_MASTER_PW
```

脚本自动完成：unlock → item list（读真库）→ 注入随机测试密钥 → `authz.evaluate`
（模式 A 弹窗批准 / 模式 B 先 `rule add` 白名单命中免弹窗）→ 断言 **Linux 子进程
收到注入 env 且值只进子进程** → 断言审计含 `channel=wsl-bridge` 且无密钥值 → 清理
（删规则/软删密钥/lock）。

完成判据：exit 0，末行 `…：N 通过 / 0 失败`。前置不满足时脚本打印
`SKIP: <原因>` 并 exit 0——按提示补齐后重跑，**不要绕过 SKIP 改测本地**。

## 6. 手动深测（可选：验证第③层弹窗与规则语义）

模式 B 验证了白名单层；要人工验证弹窗层时：

```bash
"$LK" item add secret --name MANUAL_KEY --value "manual-$(date +%s)" --purpose test
cd ~/某个测试项目目录        # cwd 会成为授权判定依据
"$LK" inject --keys MANUAL_KEY -- sh -c 'echo "${MANUAL_KEY:?未注入}"'
```

观察点（每条都是断言）：

- Windows 屏幕弹出审批窗：显示启动者（interop 链顶层）、项目目录
  （`wsl://<发行版>/...` 标注 (WSL)）、key 名、30s 倒计时；
- 点「拒绝」或不理会 → 子进程拿不到值（fail-closed 默认拒绝）；
- 点「批准」→ 子进程 echo 出注入值；stderr 无明文；
- `"$LK" audit --json | grep wsl-bridge` 有事件且不含明文；
- 收尾：`"$LK" item list` 找到 id 后 `"$LK" item delete <id>`。

探测分型专项（§7.2 设计行为，逐条验证）：

| 操作 | 期望 |
|---|---|
| `LIGHTKEY_BRIDGE=off "$LK" status` | 静默走本地 daemon（WSL 自己的库/空库），无 bridge 提示 |
| `LIGHTKEY_BRIDGE=/nonexistent "$LK" status` | 明确报错（强制路径连不上不许回落） |
| Windows 侧退出 LightKey 后 `"$LK" status` | 明确报 `bridge.no_daemon` 类错误并提示启动桌面应用 |

## 7. 排障速查

| 症状 | 原因 → 处置 |
|---|---|
| `SKIP: 未找到 Windows 侧 lk.exe` | 没装 setup.exe 或装到了非默认位置 → 重装或 `export LIGHTKEY_BRIDGE=/mnt/c/.../lk.exe` |
| `SKIP: 未找到 AppData/Roaming/lightkey/daemon.json` | 桌面应用从未启动过 → 启动一次；多用户盘符用 `LIGHTKEY_BRIDGE_HOME=/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey` |
| `SKIP: Linux lk 尚未实现 bridge 后端` | 二进制是 M2.75 之前的旧版 → 换新 Release |
| `bridge.no_daemon` | 桌面应用没在运行 → 启动并解锁 |
| `bridge.version_incompatible` | 两侧版本主.次不一致 → 两边都换成同一个 Release |
| unlock 失败 | 主密码不对（注意是 Windows 侧库的密码，不是 WSL 本地库的） |
| 弹窗超时被拒 | 30s 倒计时内没点 → 重跑该命令，或改模式 B |
