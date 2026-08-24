# Windows host 真机实测指南：WSL bridge 链路端到端复测（issue #32 第 0 步）

> 读者：运行在 **Windows 宿主**上的 AI agent，自助执行，无人类协助。
> 目的：在新基线（main ≥ `b18b769`，含 #33 PEB 偏移修复、#31 管道竞态修复）
> 上端到端验证设计链路（cross-subsystem.md §7）是否真的通：
> WSL 内 cwd `/home/u/proj` → interop 拉起 Windows `lk.exe bridge`（PEB cwd 被转写为
> UNC `\\wsl.localhost\<distro>\home\u\proj`）→ daemon 读 bridge 进程 PEB 得 UNC →
> `path_ns::canonical_project_dir` 归一化为 `wsl://<distro>/home/u/proj` → 与规则的
> `wsl://` 形态 projectDir 祖先匹配。
> 结论用于拍板「#32 是否还需要实施 bridge 自证 cwd 方案」。
> 纪律：只新建本文件所在的一次性产物与测试库条目；**不 commit**；测试用假密钥。

## §0 前置与环境自检

目的：确认环境满足、两侧二进制均为新基线自建。任何一项不过，先解决再继续，
不得带病进入 §1。

- [ ] Windows 宿主 + WSL2 发行版就绪：
      PowerShell 里 `wsl.exe --status`（或 `wsl.exe -l -v`）能看到 VERSION 2 的发行版；
      记下发行版名（下文记 `<DISTRO>`）与 Windows 版本（`cmd /c ver` 或
      `[System.Environment]::OSVersion.VersionString`）、`wsl.exe --version` 输出。
- [ ] 拉取仓库到 main ≥ `b18b769`（两侧都要；WSL 内可经
      `/mnt/<盘>/...` 访问同一 checkout，但**必须两侧分别构建**）：
      `git clone <repo>` 后 `git log --oneline -1` 确认 ≥ `b18b769`。
- [ ] Windows 侧自建 CLI（在 Windows 原生环境，如 PowerShell）：
      `cargo build --release -p lk-cli` → 产物 `target\release\lk.exe`。
      禁止使用旧 v0.1.3 安装包 / 桌面包捆绑的旧 lk.exe 测 #33/#31。
      `.\target\release\lk.exe --version` 显示 `lk 0.1.0` 属预期——workspace
      version 就是 0.1.0，发布版本号由 Release 资产名承载（#34 闸门），不要据此判旧。
- [ ] WSL 侧自建 CLI（在 `<DISTRO>` 内）：`cargo build --release -p lk-cli`
      → 产物 `target/release/lk`。同样 `./target/release/lk --version` 应为 0.1.0。
- [ ] 强制走新 lk.exe 作中继：WSL 内
      `export LIGHTKEY_BRIDGE=/mnt/<盘>/<repo路径>/target/release/lk.exe`
      （Windows 路径 `C:\...` 形式亦可）。**必须显式设置**——否则自动探测可能命中
      `%LOCALAPPDATA%\LightKey\` 下旧版 lk.exe，污染实测结论。
      数据目录不在默认位置时再加
      `export LIGHTKEY_BRIDGE_HOME=/mnt/<盘>/Users/<用户>/AppData/Roaming/lightkey`。
      探测语义（bridge_backend.rs）：`off`=强制本地逃生口；`<路径>`=强制该中继；
      未设且在 WSL=自动探测；装了连不上=明确报错绝不静默回落本地；没装=静默本地。
- [ ] 选择守护形态：推荐**纯 CLI daemon + 脚本 `--auto-approve`** 路径
      （降低对审批 UI 的依赖）。Windows 上任一本地 `lk.exe` 命令会自动拉起
      CLI 守护实例并写 `%APPDATA%\lightkey\daemon.json`
      （数据目录解析见 crates/lk-daemon/src/dirs.rs：`--dir` > `LIGHTKEY_HOME`
      > `%APPDATA%\lightkey`）。先跑一次
      `.\target\release\lk.exe status` 确认 `daemon.json` 已生成。
      **必须有桌面壳的步骤**：仅交互审批模式（E2E 不带 `--auto-approve`、或 §3
      中未命中规则期待弹窗的实验）需要桌面应用提供审批弹窗；纯 CLI 下这类请求
      以 `no_ui`（无审批界面）拒绝，属预期而非缺陷。
- [ ] 准备主密码：Windows 侧库的主密码（E2E 直接操作真实库）。无人值守时经
      环境变量 `LK_CROSS_MASTER_PW` 提供（脚本硬性要求，缺失即退出码 2）。
- [ ] 若库未初始化：`.\lk.exe init` 设测试主密码（≥8 位），抄录一次性恢复码后
      可丢弃；已初始化则直接解锁即可。

失败记录要求：每项记录确切命令、完整 stderr、退出码；环境信息
（Windows 版本 / `wsl.exe --version` / 发行版名 / 两侧 `--version` 输出）留档进 §5 报告。

## §1 基线冒烟（Windows 本地，不涉及 WSL）

目的：证明 #33 已修好——Windows 本地 inject 能读到 IPC 对端真实 cwd（不再恒
`no_cwd`）；并压测 #31 回归（管道竞态不再间歇误杀）。

- [ ] 建 Windows 本地规则（PowerShell，目录必须真实存在）：
      ```powershell
      mkdir C:\lk-smoke; cd C:\lk-smoke
      .\target\release\lk.exe unlock   # 交互输入主密码；脚本化可 echo pw | .\lk.exe unlock --stdin
      .\target\release\lk.exe rule add C:\lk-smoke "cmd *" --name smoke LK_SMOKE_FAKE
      .\target\release\lk.exe item add secret --name LK_SMOKE_FAKE --value "fake-not-a-real-key" --purpose retest
      ```
      期望：三条命令退出码均 0；`rule list` 能看到 `smoke` 一行
      （格式：id\tname\tproject_dir\tcommand\tkeys）。
- [ ] 本地 inject（同目录内执行；daemon 从 IPC 对端 PID 读到的 cwd 即 `C:\lk-smoke`）：
      ```powershell
      .\target\release\lk.exe inject --keys LK_SMOKE_FAKE -- cmd /c echo %LK_SMOKE_FAKE%
      ```
      期望：stdout 为 `fake-not-a-real-key`，退出码 0。
      失败时记录完整 stderr：若为 `lk inject: 已拒绝（无法确定工作目录）`，
      即拒绝原因 `no_cwd`——#33 在本机未生效，停止并回报（后续章节结论全部改判）。
- [ ] 反向对照（可选但建议）：`cd C:\` 后重跑上一条，期望被拒
      （目录不匹配，走第③层审批或 `no_ui`/`timeout`），**且拒绝原因不是 `no_cwd`**
      ——这是「cwd 读得到但不匹配」的基线证据。
- [ ] #31 回归压测（连续 20 次 status 统计成功率；旧基线约 85% 失败）：
      ```powershell
      $ok = 0; foreach ($i in 1..20) { .\target\release\lk.exe status *> $null; if ($LASTEXITCODE -eq 0) { $ok++ } }; "OK: $ok/20"
      ```
      期望：20/20 或接近全过（≥19/20 视为通过）。逐次失败的 stderr 全部留档
      （传输类报错 = #31 未根治的证据）。
- [ ] 清理冒烟痕迹：
      ```powershell
      $id = (.\target\release\lk.exe rule list | Select-String smoke) -split "`t" | Select-Object -First 1
      .\target\release\lk.exe rule remove $id
      .\target\release\lk.exe item delete <上面 add 返回的 id>
      ```

## §2 主事件：WSL bridge E2E 全量

目的：一条命令跑完官方跨子系统 E2E，逐步骤留档。脚本行为以
`scripts/e2e_cross_subsystem.sh` 为准（用法
`bash scripts/e2e_cross_subsystem.sh [lk-binary-path] [--auto-approve]`，
默认二进制 `target/debug/lk`——显式传 release 路径）。

- [ ] 在 WSL 内执行：
      ```bash
      export LIGHTKEY_BRIDGE=/mnt/<盘>/<repo>/target/release/lk.exe
      export LK_CROSS_MASTER_PW='<Windows侧主密码>'
      bash scripts/e2e_cross_subsystem.sh target/release/lk --auto-approve
      ```
      注意：脚本操作**真实 Windows 库**（建密钥→断言→软删→rule remove→lock），
      密钥值运行时随机生成不进仓库；这就是不能拿真密钥库当小白鼠之外无需另备
      fixture 的原因。
- [ ] 先看是否 SKIP（exit 0 且打印 `SKIP: ...`）。四种 SKIP 门与区分口径：
      1. `宿主不是 WSL2` / `WSLInterop 未启用` → 环境前置不满足，修环境；
      2. `Windows 侧未安装 LightKey 桌面应用` → `%APPDATA%\lightkey\daemon.json`
         缺失。若你已在 §0 用纯 CLI daemon 生成过它，检查路径/`LIGHTKEY_BRIDGE_HOME`；
         这是**前置不满足**，不是链路失败；
      3. `未找到 Windows 侧 lk.exe` → 未设 `LIGHTKEY_BRIDGE` 且已知安装位置没有；
         显式设置后重跑；
      4. `Linux lk 尚未实现 bridge 后端` → WSL 侧二进制是旧的（status stderr 无
         「经 bridge」提示行），重新自建。
      SKIP ≠ 真失败；只有前置全过后的 ✗ 才计入判定矩阵。
- [ ] 逐步骤核对（脚本输出 `== N.` 编号 + ✓/✗ 行），重点：
      - 步 1 连接目标可见性：`lk status` stderr 含「→ 经 bridge 连接 Windows 桌面
        守护实例（版本 …）」；
      - 步 2 unlock 经 bridge 成功；若报 `bridge.no_daemon`：先启动 Windows 侧
        守护实例（桌面应用，或 Windows 侧跑一次 `.\lk.exe status` 拉起 CLI daemon）再重跑；
      - 步 5（**历史故障点**，原第 5 步 = authz.evaluate → 注入）两处断言逐一核对：
        `rule add（命中 sh *，免弹窗）`（脚本 L159–161，显式
        `wsl://$WSL_DISTRO_NAME<PROJ>` 规范形）与
        `inject（经 bridge）exit 0` + 子进程 env 值比对 + lk 自身 stderr 不泄漏
        密钥值（脚本 L166–177）。此前链路全断即卡在此步：inject 因 daemon 读
        bridge PEB 得不到 cwd 而 `no_cwd` 拒绝；
      - 步 6 审计含 `channel=wsl-bridge` 事件且不含密钥值；
      - 步 7 清理生效（规则移除、密钥 `[deleted]` 软删、lock 成功）。
- [ ] 记录最终 `N 通过 / M 失败` 与每一行 ✗ 的原文。
- [ ] 交互模式补充（仅当有桌面壳且时间允许）：去掉 `--auto-approve` 重跑一次，
      在 30s 倒计时内人工点批准；无桌面壳则跳过并在报告标注 `no_ui` 路径未覆盖。

## §3 手工细查（E2E 全绿存疑或需定点证据时）

目的：把「通/不通」拆解成可归因的单点观测。均在 WSL 内执行，
`export LIGHTKEY_BRIDGE=<新 lk.exe>` 保持不变。

- [ ] 探针 A（匹配目录 → 应放行）：
      ```bash
      mkdir -p ~/proj && cd ~/proj
      ./target/release/lk rule add "wsl://<DISTRO>$HOME/proj" "sh *" --name probe-a LK_PROBE_FAKE
      ./target/release/lk item add secret --name LK_PROBE_FAKE --value fake-probe-value
      OUT="$(./target/release/lk inject --keys LK_PROBE_FAKE -- sh -c 'echo -n "$LK_PROBE_FAKE"')"
      echo "rc=$? out=$OUT"
      ./target/release/lk audit --json --tail 10 | grep -E 'wsl-bridge|authz'
      ```
      说明：必须用**显式 `wsl://<distro>/…` 规范形**——非交互环境下按默认发行版
      解析的折算会被明确拒绝并提示改用规范形（防静默错配，main.rs
      resolve_wsl_rule_dir）。期望：注入成功；审计最新 authz 事件
      `channel=wsl-bridge`。
- [ ] 探针 B（不匹配目录 → 应拒绝但**原因不是 no_cwd**）：
      ```bash
      cd /tmp && ./target/release/lk inject --keys LK_PROBE_FAKE -- sh -c true
      ```
      期望：`lk inject: 已拒绝（…）`，括号内是拒绝原因文案。判定关键：
      - `无法确定工作目录`（=`no_cwd`）→ daemon 在 interop 链下**完全读不到**
        bridge 进程 PEB cwd → 支持方案 A（bridge 自证 cwd）；
      - 其他原因（`未获授权`/审批 `timeout`/`no_ui` 等）→ **cwd 读到了**，只是
        目录不匹配 → PEB 解析在 interop 下可用，问题只剩匹配层。
      这一步是指挥棒：两种结果对应 §4 两行不同结论，stderr 必须原文留档。
- [ ] 探针 C（读到 UNC 但匹配失败 → 用规范形核对差异）：
      若探针 B 的原因不是 `no_cwd` 但探针 A 也失败，逐项比对
      `lk rule list` 里入库的 project_dir 与理论规范形
      `wsl://<DISTRO>/home/<u>/proj`：
      - distro 名大小写（匹配大小写不敏感，不应致败；仍记录实际值）；
      - 别名/实例名不一致（`wsl.exe -l` 列出的名字 vs `$WSL_DISTRO_NAME`）；
      - 尾斜杠/重复分隔符（canonical_project_dir 会折叠，理论上不致败）;
      - 项目目录落在 `/mnt/<盘>`（drvfs）：interop 转写后 cwd 是
        `C:\...` 盘符形态而非 wsl:// 形态——此类目录应配 Windows 盘符形态规则
        （bridge 后端下 `lk rule add X:\...` 直通入库），不要用 wsl:// 形态。
      把每个差异样本（原始 cwd 推断值 vs 规则值）列入报告，供 path_ns 补缺。
- [ ] 清理：`lk rule remove <id>`、`lk item delete <id>`、`lk lock`，
      并 `lk rule list | grep probe` 确认无残留。

## §4 判定矩阵

按 §1–§3 观测组合给出结论建议（写入报告的「结论」栏）：

| # | 观测组合 | 结论 |
|---|---|---|
| 1 | §1 冒烟过 + §2 全绿 + §3 探针 A 过、B 非 no_cwd | 设计链路成立：PEB UNC→wsl:// 归一化→祖先匹配全通。**#32 可关**（bridge 自证 cwd 方案无需实施） |
| 2 | §1 冒烟过，但 §2/§3 中 inject 恒 `no_cwd` | PEB 解析在本机（native CLI）有效、但在 interop 拉起的 bridge 进程上失效 → 支持**方案 A**；附 §2 步 5 ✗ 原文与 §3 探针 B stderr |
| 3 | inject 不再 no_cwd，但探针 A 匹配失败 | path_ns 归一化缺口：列出 §3 探针 C 差异样本（UNC 原始形 vs 入库规范形），转 path_ns 修复，不支持方案 A |
| 4 | 断言结果随重跑波动 / 大量传输类报错 / §1 压测 < 19/20 | #31 未根治：附每次失败的完整 stderr 与时间戳，考虑重开或升级 #31 |
| 5 | §2 SKIP 且前置不可修复 | 本次无结论；报告中列明卡在哪个 SKIP 门，勿臆测链路状态 |

注意单一故障可级联：先按 4→2→3→1 的顺序排除（传输不稳会让上层断言随机挂），
再下结论。

## §5 证据采集与回报格式

- [ ] 环境信息块：Windows 版本、`wsl.exe --version`、发行版名、两侧
      `lk --version` 原样输出、`git log --oneline -1`（两侧各一份）、
      `LIGHTKEY_BRIDGE`/`LIGHTKEY_BRIDGE_HOME` 设置值。
- [ ] 每个 ✓/✗ 断言保留：原样命令、原样 stdout/stderr、退出码。禁止转述、
      禁止截断错误消息。
- [ ] 审计证据：相关步骤后各取一次
      `lk audit --json --tail 10`（需库处于解锁态；锁定后先 `lk unlock --stdin`）
      片段，确认 `channel=wsl-bridge` 与 starter 链；也可直接读
      `%APPDATA%\lightkey\audit.log`（crates/lk-core/src/audit.rs `AUDIT_FILE`）。
- [ ] 回报结构：环境信息 → §1 结果 → §2 逐步结果与总分 → §3 各探针结果 →
      按 §4 给出唯一一行结论建议（含矩阵行号）→ 遗留异常清单。
- [ ] 所有原始文本放代码块，保留编码原貌（中文错误文案勿翻译）。

## §6 安全与纪律提醒

- 测试密钥一律假值（如 `fake-not-a-real-key`）；**真实密钥不进测试库、不出现
  在任何命令行参数/stdin/报告里**。fixture 密钥不入库（testing.md 纪律）。
- E2E 与手工探针操作的是真实 Windows 库：跑前确认库里没有同名真实条目会被
  误删；跑后核对清理断言（rule remove 生效、item `[deleted]`、lock 成功）。
- 审计日志与报告中的项目路径属轻度敏感信息：回报时可保留结构、对用户名段
  打码（如 `/home/<user>/proj`）；`daemon.json`、`session.token`、恢复码一律
  不外传、不入报告。
- 本指南执行过程不改仓库代码；唯一落盘产出是测试期间的数据目录变化与本文件
  同级的实测报告（由执行 agent 另行留存），**不 commit、不推分支**。
