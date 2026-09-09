# workflow: issue-autopilot

**一句话**：GitHub 新 issue → 无人值守分诊 → 能力匹配的宿主认领并在独立 worktree 实现 → 开 PR → CI 绿自动合并；卡住时用 NEEDS-HUMAN 协议把人拉进来，人回复后自动续跑。

- 状态：**设计完成（grill 已收敛，无悬空问题），未实现**。
- 触发：**事件 + 调度混合**（事件 = 新 issue / 新评论 / PR 状态变化；调度 = 每 15 分钟一轮，本机常驻）。
- Checkpoint：**push-right** —— 人在两处介入：(1) `needs-human` 回复；(2) 驳回 PR / 抢单。其余全自动。
- 权威：本文件。实现物在 `scripts/autopilot/`，与本文件冲突时以本文件为准。
- 相关：`docs/agents/issue-tracker.md`、`docs/agents/triage-labels.md`、`/triage`、`/implement`、`AGENTS.md`（交付纪律）。

---

## 1. 宿主与身份

循环的调度器（poller）跑在**任意一台登记在册的开发机**上；当前已知两台：本机 Linux 容器（自动，cron 驱动）与 OWNER 的 Windows 机（**人为主动触发，不装 cron**；运行时 = **PowerShell 前门 + Git Bash 引擎**，A14，登记步骤见 §13.8）。

- 每台宿主一份本地配置 `~/.config/lightkey-autopilot/host.toml`（**绝不进仓库**）：

  ```toml
  host_id = "linux-ws1"          # 全局唯一，出现在所有心跳/跳账文本里
  claimed_capabilities = ["rust-workspace", "frontend-vitest", "windows-cross-check"]
  provider = "bailian-plan-personal"
  model_triage = "qwen3.8-flash"
  model_implement = "qwen3.8-flash"   # 船长定的实现模型
  thinking_triage = "low"             # 闭集 off/minimal/low/medium/high/xhigh/max
  thinking_implement = "max"          # 实现走最高档（模型不变、档位拉满）
  budget_implement_tokens = 2000000  # 单次 implement 累计 usage 超阈即 kill（§11.1）
  alert_webhook = ""             # 空 = 只用 heartbeat-stale 标签；非空 = 心跳超时 POST 该 URL
  tracking_issue = 0             # 本 workflow 的 pinned tracking issue 号（见 §9）
  ```

  模型与推理档位**只在这里配**，不依赖 `~/.pi/agent/settings.json` 默认值（理由见 §11.1）。

  `claimed_capabilities` 只是**候选声明**；判定一律以 §7 的动态探测结果为准（fail-closed）。
  声明里没有、探测却有 → 用探测结果并打警告；声明里有、探测不过 → 能力缺失。

- 同机互斥（单 poller）：`flock ~/.local/state/lightkey-autopilot/poll.lock` 全程持有，拿不到就本轮 exit 0。
- **跨机互斥不引入分布式锁**：`agent-working` 标签 + §4 步骤 2 的「写前重读」是全部机制。理由：Windows 侧由人主动触发，人本身就是互斥的 arbiter；加锁只会造出新的死锁与孤儿锁。

## 2. 词汇（canonical）

**标签**（tracker 实际字符串 = canonical 名，需先创建，见 §10）：

| 标签 | 归属 | 含义 |
| --- | --- | --- |
| `needs-triage` `needs-info` `ready-for-agent` `ready-for-human` `wontfix` | `/triage` 五角色 | 分诊状态，语义见 `/triage` |
| `agent-working` | **autopilot 专属** | 已被某宿主认领、正在跑或有活动 PR（不是 triage 角色，`/triage` 不许读写） |
| `needs-human` | **autopilot 专属** | agent 卡在半路，等**维护者裁决**（≠ `needs-info` 的「等报告人补信息」） |
| `heartbeat-stale` | **autopilot 专属** | autopilot 心跳超时（§9），打在 tracking issue 上 |
| `bug` / `enhancement` / `documentation` | 既有 | 类别角色 |

**状态词**：`claimed`（= `agent-working`）、`blocked-on-human`（= `needs-human`）、`skipped-on-host`（本宿主能力不足，仅记跳账，见 §6）。

**能力词表**（绝对、跨宿主同形，§7）：`rust-workspace`、`frontend-vitest`、`tauri-shell`、`windows-cross-check`、`wsl2-desktop-e2e`、`release-build`。

## 3. issue 状态机（autopilot 视角）

```
unlabeled ──/triage──┬──> needs-triage ──> ready-for-agent ──> agent-working ──> (PR merged) 关 issue + 摘标签
                     ├──> needs-info   ──(报告人回复)──> needs-triage
                     ├──> ready-for-human（终态：人来做 / 本机做不了且 7 天无宿主认领）
                     └──> wontfix  ✗ autopilot 无权（§5）
agent-working ──卡住──> needs-human ──(OWNER/MEMBER 回复)──> agent-working（续跑，不重置配额）
agent-working ──(人 assign 自己 / 评论 "mine")──> 摘 agent-working，现场保留，不重开
```

约束：每个已分诊 issue **恰好一个类别标签 + 恰好一个状态标签**；`agent-working` 与 `needs-human` 互斥，且都不与五状态标签同时出现（认领时摘 `ready-for-agent`，见 §6 步骤 5）。

## 4. 一轮的固定阶段（顺序即语义，不得调换）

0. **总开关**：读 tracking issue 标题，含 `[PAUSED]` → 心跳记一行「已暂停」后 exit 0。
1. **轮次锁**：`flock`；持有每日配额计数器（`~/.local/state/lightkey-autopilot/quota-<date>.json`）。
2. **收尾扫描（回收优先于开工）**：对每个带 `agent-working` 的 issue：
   - 其 PR `merged` → 摘 `agent-working`；确认 issue 已关（未关则由调度器关闭并附 PR 链接）；删远端 `autopilot/<n>` 分支；`git worktree remove` + `git fetch --prune`；心跳记一行。
   - 其 PR `closed`（被驳回）→ 摘 `agent-working` 打 `needs-human`，**保留分支与 worktree**（驳回必有理由，理由不落盘 agent 只会重犯）。
   - checks 红 / 无 PR 且 2h 内无心跳戳（§8）→ 视认领已泄漏：按 §8 重试规则处置（配额未尽则重新起，尽则 `needs-human`）。
   - 被人类抢单（assignee 非空且非 bot，或 `agent-working` 评论戳之后出现 OWNER/MEMBER 的 `mine`）→ abort 子进程、摘 `agent-working`、保留现场、**永不重开**。
3. **分诊阶段**（预算 §11）：对 unlabeled / `needs-triage` 的 issue 起 `pi -p "/skill:triage …"`，权限见 §5。
4. **恢复阶段**：对 `needs-human` 且 §8 判定「OWNER/MEMBER 已回复」的 issue → 换回 `agent-working`，进入认领。
5. **认领 + 实现阶段**：见 §6，最多 **1** 个（并发=1）。
6. **PR 阶段**：见 §10（auto-merge 闸门在这里）。
7. **心跳**：写 tracking issue（§9），含跳账区与配额余量；**失败也要写，且 `last-ok:` 行必须是本轮第一个写入动作**（否则长阶段卡死时看门狗拿不到准确心跳）。

任何阶段失败都要让本轮以非 0 退出并把摘要塞进心跳，**禁止静默**。

### 4.1 启动层与单实例（`scripts/autopilot/ctl.sh`，已落地）

需求：**重复敲 `start` 不能起出第二个循环**。契约：

- **真相 = 内核持有的 flock，不是 pid 文件**。pid 文件有 TOCTOU 竞态、被 SIGKILL 后残留（谎报在跑）、pid 可被复用（谎报没跑）；pid 文件只当人读提示，判定一律 `fuser loop.lock`。
- **硬闸门在子进程里**（`flock -n` 抢到才跑），父进程事前的检查只为人话提示。5 个 `start` 并发冲进 → 实测仍只有 1 个实例持锁（回归钉住）。
- **两把锁各司其职**：`loop.lock` = 常驻实例锁（`ctl.sh start`）；`poll.lock` = 单轮互斥锁（`poll.sh` 自己抢，§4 步骤 1）。loop 在轮次之间**不持** `poll.lock`，所以人工 `run-once` / timer / 循环 之间是**排队**关系，不会被误判为“已在跑”。
- **子进程必须关掉继承的锁 fd**（`9>&-`），否则 `fuser` 报出一堆 PID，看活层会误判为多实例（实踩过）。
- `stop` = TERM 整个进程组等本轮收尾，30s 后 KILL；**只在确认无人持锁后才删锁文件**（删一个还被人持着的锁 = 下个 `start` 能再起一个实例）。
- 两种驱动方式**二选一**（同一对锁，不会打架但会互排队）：`ctl.sh start`（常驻，手工起）或 `ctl.sh install` + systemd user timer（推荐：重启自动续、崩溃可拉起、有 journal）。

## 5. 分诊的自主权限边界（硬约束）

允许（agent + 调度器代码双重校验）：

- 读写类别/状态标签：`needs-triage`、`needs-info`、`ready-for-agent`、`ready-for-human`（+ 既有类别标签）。
- 发评论：Triage Notes、agent brief（带 `Needs:` 行）、autopilot AI 免责声明（`/triage` 规定）。
- 读任何 issue / PR / diff；跑只读命令。

**禁止**（调度器在 `pi` 退出后逐条 diff 标签与动作，命中即回滚 + `needs-human`）：

- `wontfix`、关闭 issue、标 `duplicate`、写 `.out-of-scope/`。
- 读或写 `agent-working` / `needs-human`（autopilot 专属，只有调度器能写）。
- 修改别人的评论、改 milestone/assignee（除认领所需的 assign bot）。
- 任何「终结性」判定：拒绝与判死是维护者的价值判断，错了不可逆。

送进 `ready-for-agent` 之前，`/triage` 必须完成 §7 的 `Needs:` 判定 —— 不可本机验证的活**在分诊阶段**就该落 `ready-for-human` 并写明缺哪台机器，而不是让实现阶段撞墙。

## 6. 认领（选单与幂等）

**资格过滤**（全满足才可入池）：`ready-for-agent` ∧ 无 assignee ∧ §7 探测能力覆盖该 brief 的 `Needs:` ∧ 无未完成 blocker（GitHub 原生依赖 `issue_dependencies_summary.blocked_by > 0`，退化到 body 里的 `Blocked by:` 行）∧ 未被 §8 配额耗尽。

**排序**：创建时间最旧优先（tie-break：issue 号小者优先）。**不用**优先级标签、不用里程碑顺序 —— 确定性优先，插队走人工（人 assign 自己即可抢单，见 §4 步骤 2）。

**认领动作（顺序敏感）**：

1. **写前重读** issue（跨机唯一 CAS 尝试）：标签仍是 `ready-for-agent` 才继续；否则本轮放弃该 issue。
2. 摘 `ready-for-agent`，打 `agent-working`，评论认领戳（§8 格式）。
3. 建现场：`git fetch origin && git worktree add .autopilot/worktrees/<n> -b autopilot/<n> origin/main`；worktree 内独立 `--session-dir`。
4. 起 §7/§11 的实现子进程。

**跳账（本宿主做不了，别的宿主可能做得了解决"误判"）**：

- **标签一律不动**（保留 `ready-for-agent`），永不因「本机做不了」打 `ready-for-human`。
- 在 tracking issue 心跳的 `## skipped-on-host` 区追加一行：
  `skipped #173 host=linux-ws1 missing=tauri-shell at=2026-09-07T12:00Z`（同一 host+issue 只保最近一条，防膨胀）。
- 降级条件：某 issue 在心跳里被**所有在册宿主**跳过、且无人认领、且 `ready-for-agent` 停留 **> 7 天** → 调度器打 `ready-for-human`，评论必须逐条列出「哪几台宿主 / 缺哪个能力 / 需要谁开哪台机器」。这是终结性判定，但由**超时 + 全宿主否定**共同触发，不由单机一念决定。

## 7. 能力判定

`bash scripts/autopilot/probe-capabilities.sh` 输出一行 JSON，判定只读它：

```json
{"host_id":"linux-ws1","ok":true,"capabilities":{"rust-workspace":true,"frontend-vitest":true,
 "tauri-shell":false,"windows-cross-check":true,"wsl2-desktop-e2e":false,"release-build":false},
 "missing_reasons":{"tauri-shell":"webkit2gtk-4.1 not installed"},"disk_free_gib":41.2,"ts":"…"}
```

探测契约（每项必须是**主动验证**，不许只看配置文件）：

| 能力 | 探测方式 |
| --- | --- |
| `rust-workspace` | `cargo --version` + `cargo test -p lk-core --no-run` 能过 |
| `frontend-vitest` | `node --version` + `frontend/node_modules` 存在或 `npm ci` 可成 + `npm test -- --run` 冒烟 |
| `tauri-shell` | Linux：`pkg-config --exists webkit2gtk-4.1` 且 `cargo check -p lk-app` 可行；Windows：原生工具链在 |
| `windows-cross-check` | conda env `lightkey-mingw` 存在 + `cargo check --workspace --target x86_64-pc-windows-gnu` 冒烟 |
| `wsl2-desktop-e2e` | WSL2 interop 可用 + Windows 桌面包已装（`e2e_cross_subsystem.sh` 前置检查不 SKIP） |
| `release-build` | 仅 OWNER 手工：探测**恒为 false**，agent 永不可得 |

- 探测失败 / 超时 / JSON 不合法 ⇒ **一切能力视为 false**（fail-closed）。
- brief 的 `Needs:` 行由 `/triage` 写，格式固定：`Needs: rust-workspace, frontend-vitest`（能力标签闭集，出现词表外的名字 → 调度器拒绝进入认领并打 `needs-info`，等维护者改写）。**绝不写机器名/宿主名**——需求是 issue 的固有属性，"我做不了"是宿主的属性。

## 8. 现场、NEEDS-HUMAN 协议与配额

**认领戳**（`agent-working` 的第一条评论，后续实现每 10 分钟覆盖式更新 `last-heartbeat`）：

```markdown
## AGENT-WORKING [linux-ws1/2026-09-07T11:40Z]
- run-id: r-173-20260907-1140
- host: linux-ws1
- branch: autopilot/173
- worktree: /root/code/projects/lightkey/.autopilot/worktrees/173
- attempt: 1/2
- last-heartbeat: 2026-09-07T11:52Z
```

**卡住时**（判定不了、缺权限、连续失败、护栏命中）：

```markdown
## NEEDS-HUMAN [linux-ws1/r-173-…]
**卡在哪**：<一句话 + 阶段名>
**需要你决定**：<必须是单句、可 Y-N 或二选一回答的问题>
**已尝试与证据**：<命令 + 失败输出摘要，≤15 行>
**现场**：branch `autopilot/173` @ `<sha>`，worktree 保留
**配额**：attempt 2/2（耗尽后不再自动续跑）
```

**恢复判定**：该锚点评论**之后**存在 `authorAssociation ∈ {OWNER, MEMBER}` 的新评论 → 恢复。只有 `NONE` / `CONTRIBUTOR`（外部报告人）回复不算恢复（那是 `needs-info` 的信号，走 `/triage` 的路）。
**续跑输入**：若维护者回复以 `AUTOPILOT: ` 开头，调度器把该行原文**原样注入续跑 prompt 第一段**；否则 agent 自行读评论。回复即视为新尝试的输入，**不重置** `attempt` 计数。
**现场保留**：`needs-human` 期间分支/worktree 一律不删（续跑要用）；摘 `agent-working`、打 `needs-human`。

## 9. 状态面：labels（真相）+ pinned tracking issue（心跳）+ 看活两层

真相只在标签与 PR；tracking issue 是人可读的、可 grep 的投影，**不是状态源**（除 `[PAUSED]` 开关与 §6 降级所需的跳账历史）。本地除配额计数器/日志外**不留任何状态**（机器坏了从 GitHub 完全重建）。

**机器可读契约（唯一的跨层接口，必须逐字实现）**：正文里恰好一行

```
- last-ok: 2026-09-09T03:12:44Z
```

以 `last-ok:` 开头（带冒号）、值为 ISO-8601 UTC。`poll.sh` **每轮最先写它**（无论本轮成败；写在其他任何阶段之前，失败路径也要写），`status.sh` 与 GitHub 侧看门狗都只认这一行。人读区域用 `last-ok ` （无冒号）等写法，不会被误匹配。

tracking issue 正文骨架（调度器整段重写，人可读区域用 `<!-- human -->` 包裹保留）：

```markdown
# issue-autopilot — heartbeat [PAUSED?]   host=linux-ws1  last-run=…  next≈…
## 本轮
- 结论: OK | PARTIAL | FAIL(<原因>)
- 认领: #173 (attempt 1/2, branch autopilot/173, PR #180)
- 分诊: #181 → ready-for-agent   #182 → needs-info
- 待你: #175 NEEDS-HUMAN since 2026-09-06（缺一个"是否支持 X"的裁决）
- PR: #180 CI green, automerge ON
## 配额
implement-today 2/3 · round-timeout 60m · disk 41 GiB
## skipped-on-host
skipped #173 host=linux-ws1 missing=tauri-shell at=…
## 循环健康
- last-ok: 2026-09-09T03:12:44Z        ← 机器可读契约行，勿改格式
- 阈值 45m · 告警 webhook: off · host=linux-ws1
```

### 9.1 看活两层（回答「这个循环还活着吗」）

判定逻辑**不得只跑在本机** —— 否则机器关机 / cron 停掉时，看门狗和病人一起倒。

| 层 | 载体 | 能看到什么死法 | 看不到什么 |
| --- | --- | --- | --- |
| **L1 GitHub 侧**（外部见证） | `.github/workflows/autopilot-watchdog.yml`（**已落地**；`*/30` + dispatch，权限 = `issues: write`，Variable 经 runner `vars` 上下文注入，不装工具链） | 宿主关机、cron 没装/停了、子进程卡死、轮次持续崩、`last-ok:` 行丢失 → 打 `heartbeat-stale` + 一次评论（已含该标签则不重复评论），恢复后自动摘；`[PAUSED]` 视为人主动停，不报警 | 「循环活着但活干错了」（只能靠 PR 评审 + revert）；Actions 自己长期不调度（私有库 60 天无活动会被 GitHub 停 schedule → 靠 `status.sh` 的看门狗年龄检查发现） |
| **L2 本机一眼** | `bash scripts/autopilot/status.sh [--json]`（verdict/退出码：`ALIVE` 0 / `SUSPECT` 1 / `PAUSED` 0 / `BROKEN` 2） | 心跳年龄、`heartbeat-stale` 是否在（**在即判死**，哪怕本机心跳看着新）、**L1 自己最近一次运行与结论**、轮次锁持有者、今日配额、在跑 issue、日志尾、`host.toml`/`gh` 可用性 | 机器整个关机时你自己就不在这台机器上（所以必须有 L1） |

L1 是**唯一允许的非构建/非发布 `schedule` workflow**（补充拍板 #29，2026-08-27「非 PR 提交不触发构建」裁定不变）。它需要仓库 Variable `AUTOPILOT_TRACKING_ISSUE=<issue 号>`，经 runner 的 `vars` 上下文注入（不走 REST：GITHUB_TOKEN 即便带 `actions: read` 也调不动 actions variables API，实测 403 被 catch 吞成「未配置」）；未配置时 L1 **fail loudly**（`core.setFailed`），不静默通过。

**看门狗自身的心跳校验（严格形状）**：`last-ok:` 的值必须是 `YYYY-MM-DDThh:mm[:ss]` + `Z`/偏移量。宽松解析会出两类**假装活着**的假错：`date -d ""` 返回今日零点，无时区的 `2026-09-09T03:12` 在 JS 里按本地时区解析（可偏差数小时）。两种均归为「无心跳」。

**启动顺序提醒**：L1 合进 main 时 `poll.sh` 还不存在 → 看门狗会因找不到 `last-ok:` 而报失活（属预期的「真死」，不是 bug；Actions 变红本身就是信号）。要暂不报：建好 tracking issue + 设好 Variable，标题留 `[PAUSED]`（§9.1 L1 对暂停态不报警）。

**看门狗的看门狗**：不再加一层（会无穷回归）。收敛办法是把 L1 自身的健康塞进 L2 的输出：`status.sh` 检查「看门狗最近一次运行 > 120 分钟没跑」→ 报警。人只有一条命令要记：**`bash scripts/autopilot/status.sh`**。

两层的回归测试：`bash scripts/autopilot/tests/status.t.sh`（假 `gh` + 假 HOME，不联网；钉住心跳契约的四种畸形输入与 `[PAUSED]` 不报警）。

## 10. PR 契约与 auto-merge

- 分支 `autopilot/<n>`；一个 PR 恰好一个 squash 提交，message `<type>(<scope>): <subject> (#<n>)`。
- **只允许 push** `refs/heads/autopilot/*`；禁止 `--force`、禁止碰 `main` 或他人分支（调度器在子进程结束后 `git ls-remote` diff 新 ref，命中白名单外 → 立即 revoke + `needs-human`）。
- PR 正文模板（必填四段）：`Closes #<n>` / **Spec 依据**（`docs/*.md §` + issue brief）/ **本机验证结果**（跑了哪些命令、通过与否、缺哪个能力）/ **护栏命中**（denylist 结果）/ **NEEDS-HUMAN 历史**。
- 合并方式 **squash**。`Closes #<n>` 缺失 → 不许开 auto-merge（合并即自动关 issue，循环只补标签与清理）。
- **auto-merge = CI 全绿即自动合并（`gh pr merge --auto --squash`）**，但两道独立闸：
  1. **分诊前置**：改动面可能命中 denylist 的需求不进 `ready-for-agent`。
  2. **合并闸门**：PR diff 命中 denylist → **不开** auto-merge，评论说明命中项 + 打 `needs-human`。
  denylist（路径闭集）：`.github/**`（agent 改 CI = 自己放宽规则，token 有 `workflow` scope）、`crates/lk-app/**`（本机无法完整验证的部分仍需人看）、`Cargo.toml` 的 `[workspace.package] version`（#34：bump 属发版）、`Cargo.lock` 大改、`frontend/package-lock.json`、`docs/decisions.md`、`CONTEXT.md`、`docs/adr/**`、`AGENTS.md`、`docs/**` 的任何规格权威文件（规格是唯一权威，不许 agent 自己盖章）。
- PR 未合并期间 `agent-working` **不摘**（否则你会以为它还在跑）。

## 11. 预算与上限

| 项 | 值 | 超限处置 |
| --- | --- | --- |
| 并发 implement | 1 | 排队，不并行 |
| 每 issue 自动重试 | 2（`attempt n/2`，NEEDS-HUMAN 续跑不重置） | 第 2 次仍失败 → `needs-human` 停手（绝不死循环烧钱） |
| 每日 implement 启动 | 3 | 配额尽 → 本轮不认领，心跳记「配额用尽」 |
| 每轮分诊 issue 数 | 3 | 其余留到下轮（最旧优先） |
| 单轮墙钟 | 60 分钟 | kill 子进程，issue **打回 `ready-for-agent`**（超时是宿主问题，不是活的问题，不该污染 `needs-human`） |
| 子进程 stdout | `--mode json` 落 `runs/<issue>/<ts>.jsonl`，保留 30 天 | — |
| 单次 implement 累计 token | `budget_implement_tokens`（默认 2M） | 超阈 kill + 打回 `ready-for-agent`（活太大就是不该一轮干完，不是宿主问题也不是该问人） |
| 磁盘余量 | < 15 GiB | 整轮不启动，心跳报缺盘 |
| `CARGO_TARGET_DIR` | 与主仓共享（复用缓存，并发=1 天然串行） | — |

### 11.1 模型与推理档位从哪里配（只认一个入口）

pi 的解析优先级：`--provider` / `--model` / `--thinking` 旗标 **>** `.pi/settings.json`（项目层，需 `--approve` 才加载）**>** `~/.pi/agent/settings.json`（全局层）。
**`PI_MODEL` / `PI_REASONING_LEVEL` 不是配置入口** —— 它们是 pi 注入给「自己起的子进程」看的当前会话报告面（`docs/environment-variables.md`），在 cron 里设它们选不出模型。循环**只用旗标层**，值从 `host.toml`（§1）取：

| 阶段 | 模型 | 推理档位 | 为何这么分 |
| --- | --- | --- | --- |
| 分诊（`/skill:triage`） | `model_triage`（廉价档） | `thinking_triage`（`low`） | 分类 + 写 brief，不需长链推理；跑量大 |
| 实现（`/skill:implement`） | `model_implement` = `qwen3.8-flash` | `thinking_implement` = `max` | 船长定：**模型不换、推理档位拉满**。实测该模型 900K 上下文 / **900K 输出上限**（对比 `qwen3.8-max` 1M 上下文但输出只 128K），写大 diff 反而更不容易被输出截断 |
| 续跑（NEEDS-HUMAN 恢复） | = `model_implement` | = `thinking_implement` | 同难度任务不因续跑降档（降档 = 同一活两种质量） |

细节：

- 档位写法二选一：`--model <id> --thinking high`，或后缀单参 `--model <provider>/<id>:high`（后缀优先）；档位闭集 `off\|minimal\|low\|medium\|high\|xhigh\|max`，模型不支持的档位由 provider 侧 `thinkingLevelMap` 映射/剔除。
- 每档的 **token 预算**在 `~/.pi/agent/settings.json` 的 `thinkingBudgets` 里改（全局层）；除非真要改预算否则别动，循环不读全局设置。
- 不用 `defaultModel` / `/model` 的原因：那是你交互时随手改的，夜里的批处理跟着它漂 = 不可复现，而且 `runs/*.jsonl` 无法回答“当时是哪个模型写的”。
- 成本计量：`--mode json` 顶层 `usage` 是累计值（部分 provider 只在完成时报，中途可能为 0），预算守护取历史 max，kill 前把已用 token 写进心跳。
- **可复现要求**：`pi-run.sh` 必须把本次实际生效的 `provider/model/thinking` + 累计 token 写进 `runs/<issue>/<ts>.jsonl` 首行与心跳「本轮」区 —— 你放弃了逐个评审（§10 auto-merge），这套记录是唯一能回答「这坨是谁、以什么档位写进 main 的」的东西。
- **别在仓库 `.pi/settings.json` 写 `defaultModel`/`defaultThinkingLevel`**：那会同时改变你交互会话与循环的缺省（旗标仍覆盖它），属「随手一改影响夜间批处理」。选模型只走 `host.toml`。

## 12. 安全不变量（实现者必须逐条变成代码，不能只当文档）

1. 永不 `wontfix` / 关闭 / `duplicate` / 写 `.out-of-scope/`（§5）。
2. 永不 push 非 `autopilot/*` 的 ref；永不 `--force`；永不改 `main`。
3. `needs-human` 与 `[PAUSED]` 只能由人解除（`[PAUSED]` 由人改标题；agent 无权重写 tracking 标题）。
4. 绝不触碰真实 `~/.lightkey` 数据目录与 daemon socket；一切测试用临时目录 / `file://` 模拟存储。
5. denylist 命中即不 auto-merge（§10）；`release-build` 探测恒 false，agent 永不能发版。
6. 密钥/fixture 密码不进仓库（`docs/testing.md`），不进 issue 正文，不进 `runs/*.jsonl`（写入前过一道 redact：`gh` token、`OPENAI_API_KEY` 值）。
7. 子进程结束后校验：新 ref 名单、标签 diff、PR 存在性；任何越界 → 回滚该 issue 状态 + `needs-human`，本轮继续。
8. 环境隔离：`env -u OPENAI_API_KEY` 起 `pi`（实测嵌套默认 provider 会 401），凭据只从 `host.toml` 显式传 `--provider/--model`。
9. `--approve` 必给（否则 `AGENTS.md` 与项目 skills 不加载，agent 会绕过交付纪律）。
10. 每轮**先写 `last-ok:` 再干其他**（§9 契约）；本轮无论如何不得跳过心跳写入（它是 §9.1 L1 的唯一判据）。
11. 任何不确定 → 打 `needs-human`，不要猜。

## 13. 实现前置动作（只能 OWNER 做）

1. 建标签：`gh label create needs-info|needs-human|agent-working …`（实测 `needs-info` 不存在，`needs-human`/`agent-working` 要新建；`heartbeat-stale` 可不管 —— 看门狗首次判失活时会自建）。
2. ~~改交付纪律~~ **已完成（2026-09-09）**：`docs/decisions.md` 补充拍板 #29 + `AGENTS.md` 交付纪律/CI 条目已修订为「autopilot PR CI 绿自动 squash 合并 + denylist 必人评」。仍归你的：改动 `docs/**` 规格权威文件本身依然不许 agent 碰（§10 denylist）。
3. 建 tracking issue 并 pin，把号写进 `host.toml: tracking_issue`，并设仓库 Variable `AUTOPILOT_TRACKING_ISSUE=<号>`（看门狗用它；没设则 §9.1 L1 会 fail loudly）。
4. 填 `host.toml`（provider/model/thinking/webhook），确认 `pi --approve` 对本项目已 trust。
   逐模型验凭据（**没有这步，夜里第一轮就会因 401 全崩**，实测默认 provider 必 401）：
   `pi auth check --provider <p> --model <model_implement> --json` → 期望
   `{"status":"ready",...}`；`pi --list-models <关键词>` 确认模型 ID 还在（模型名会过期）。
5. 装 cron/systemd timer：`*/15 * * * * bash scripts/autopilot/poll.sh >> …/cron.log 2>&1`（cron **不继承交互 shell 的 `PATH`/env**：`pi`/`cargo`/`node`/`gh` 要绝对路径或在 `poll.sh` 开头显式设 `PATH`；实测不显式给 provider 就 401，见 §12.8）。
6. 选驱动方式（二选一）：`bash scripts/autopilot/ctl.sh install` 再按提示 `systemctl --user enable --now lightkey-autopilot.timer`（重启自动续）；或 `bash scripts/autopilot/ctl.sh start` 起常驻循环（重复 start 幂等，§4.1）。试跑一轮用 `ctl.sh run-once`，停用 `ctl.sh stop`。
7. 把 `.github/workflows/autopilot-watchdog.yml` 合进 main（`schedule` 只在默认分支生效），`gh workflow run autopilot-watchdog.yml` 手工验一次能读到 tracking issue。
8. **Windows 侧登记**（第二台宿主；以下步骤在 OWNER 的 Windows 机上执行，运行时钉死为「PowerShell 前门 + Git Bash 引擎」，A14）：
   - **PowerShell 只是前门，引擎必须是 Git Bash**：交互与启动都在 PowerShell 里做，循环本体由 Git Bash 执行——日常触发就一行 `bash scripts/autopilot/ctl.sh run-once`。**绝不移植成 pwsh 原生脚本**：脚本单一实现（本机 cron 与 Windows 侧同源），`flock` 锁语义（内核持 fd、进程死自动释放）与 §12 不变量只在一处验证才算数；PowerShell 无 `flock` 等价物。
   - 前置（2026-09-09 OWNER 实测回传）：Git Bash 自带 `flock`（`bash -lc 'command -v flock'` → `/usr/bin/flock`）；`pi` 在该机可用。凭据**仍**按 §13.4 逐模型验（401 坑与平台无关）；`gh auth status` 需 OK。
   - **不装 cron/timer**，只人工 `run-once`；从交互 shell 启动 ⇒ PATH/env 即交互环境，§13.5 的 cron PATH 坑天然不适用。
   - 自己的 `host.toml`：`host_id` 全局唯一（如 `win-desktop1`）；`claimed_capabilities` 只是候选声明，判定一律以 §7 动态探测为准——Git Bash 里看到的 `cargo`/`node` 即 Windows 原生工具链，探测如实反映 Windows 环境。
   - 跨机互斥无锁（§1）：两台机同时开轮由人做 arbiter，可能白跑一轮但不会撞坏。

## 14. 已知风险（不自欺）

- **循环死亡已不再不可见（原残留，§9.1 L1 补）**：GitHub 侧看门狗能发现宿主关机与 cron 停摆；残余只剩「**看门狗自己**和 Actions 同时失灵」（私有库 60 天无活动被停 schedule / GitHub 侧故障），此时靠 L2 的看门狗年龄检查发现，或你手动 `gh run list --workflow autopilot-watchdog.yml`。
- **真相源投毒**：已合并的错误代码 = 新基线；auto-merge（OWNER 决策）把这个风险的窗口缩到 CI 时长，缓解只有 denylist + squash 易 revert。
- **规则/授权门类改动**（`docs/authorization-gate.md` 等）是安全关键，CI 绿 ≠ 正确；建议这类 issue 由你手工落 `ready-for-human`，别指望分诊 agent 判定「安全重要度」。
- **Windows 侧**：不装 cron，能力（`tauri-shell` on Windows、`wsl2-desktop-e2e`、`release-build`）实际长期为 false → 那类 issue 会稳定走 §6 的 7 天降级路径。
- **本地未验证即提 PR**：`lk-app` 改动被 denylist 挡住 auto-merge，但 agent 仍可能「写了没验证的 Rust」—— PR 正文的「本机验证结果」段是你唯一抓手。

## 15. Definition of done（实现验收）

`DRY_RUN=1`（只分诊、只跳账、不开 PR、不动标签）在真实仓库跑通 ≥1 轮 → 关闭 dry-run 后在一个**玩具 issue**（"加一行 README 说明"）上端到端跑通：`ready-for-agent → agent-working → PR → CI 绿 → squash 合并 → issue 自动关 → 标签/分支/worktree 全清 → 心跳如实`；再人工验证三条中断：`[PAUSED]` 生效、`mine` 抢单被 abort、`NEEDS-HUMAN` 回复后续跑（且 `attempt` 未被重置）。

## 16. 实现清单（文件契约）

| 文件 | 职责 |
| --- | --- |
| `scripts/autopilot/poll.sh` | **待实现**：§4 阶段编排 + §11 配额 + §12 校验；开头必抢 `poll.lock`（§4.1） |
| `scripts/autopilot/probe-capabilities.sh` | §7 JSON 契约，fail-closed |
| `scripts/autopilot/status.sh` | **已落地**：§9.1 L2 一眼看活（人用） |
| `scripts/autopilot/ctl.sh` | **已落地**：§4.1 启动层（start/stop/run-once/install + 单实例幂等） |
| `scripts/autopilot/tests/ctl.t.sh` | **已落地**：§4.1 回归 18 例（并发 start 单实例 / 锁 fd 继承 / stop 真停 / 缺 poll.sh 响亮报错） |
| `.github/workflows/autopilot-watchdog.yml` | **已落地**：§9.1 L1 外部见证（`schedule`，权限 `issues: write`；Variable 经 `vars` 上下文注入） |
| `scripts/autopilot/lib/labels.sh` | 标签读写 + §5 权限白名单校验 + 回滚 |
| `scripts/autopilot/lib/pi-run.sh` | **唯一允许出现模型参数处**：`host.toml` → `--provider/--model/--thinking` + `timeout` + `usage` 预算守护 + `runs/` 落盘（§11.1） |
| `scripts/autopilot/lib/heartbeat.sh` | §9 正文重写（保留 `<!-- human -->` 区）+ 看门狗/webhook |
| `scripts/autopilot/lib/pr.sh` | §10 denylist 判定、PR 正文渲染、`gh pr merge --auto --squash` |
| `scripts/autopilot/prompts/{triage,implement,resume}.md` | 投喂模板：issue 号 + brief 全文 + `AUTOPILOT:` 回复原文 + §12 禁令全文 |
| `scripts/autopilot/tests/*.bats` | denylist、能力词表、状态机迁移、跳账降级、配额的纯逻辑回归（待实现） |
| `scripts/autopilot/tests/status.t.sh` | **已落地**：§9.1 两层看活的离线回归（12 例） |

prompt 投喂用「调度器拼全文」而非「让 agent 自己 `gh issue view`」：禁令与 brief 必须在 prompt 里，不靠 agent 自觉；代码再校验一遍，双闸。

## 17. 决策日志（本轮 grill 收敛，编号自成体系）

| # | 决策 | 由谁定 |
| --- | --- | --- |
| A1 | 本机 cron 常驻（非 Actions）；Windows 只人为触发 | OWNER |
| A2 | 分诊只推进不终结（禁 wontfix/关闭/duplicate） | OWNER |
| A3 | `needs-info`（等报告人）与 `needs-human`（等维护者）并存 | OWNER |
| A4 | 标签即状态机 + `agent-working`；零隐藏状态；本机 flock，跨机不加锁 | OWNER |
| A5 | CI 绿即 auto-merge + denylist 双闸，squash | OWNER（推翻我推荐的「代码类必人评」） |
| A6 | 并发 1 / 重试 2 / `[PAUSED]` 总开关 / 心跳判活 | OWNER |
| A7 | 能力 = 宿主绝对声明 + 动态探测 fail-closed | OWNER |
| A8 | 「本机做不了」不动标签，只跳账，7 天全宿主否定才降级（防 Windows 误判） | OWNER |
| A9 | 四条避让协议（ref 命名空间 / 人抢单 / 宿主卫生 / CI 竞争） | OWNER |
| A10 | 哑调度器 + 两个有界 LLM 任务；实现者=代码，判断者=模型 | OWNER |
| A11 | 告警通道做成配置项，空值退化为 `heartbeat-stale` 标签 | AGENT 代决（你未指定通道） |
| A12 | 存活判定分两层：GitHub 侧 schedule 看门狗（外部见证，能发现宿主关机）+ 本机 `status.sh`；看门狗自身健康由 `status.sh` 兜 | OWNER（明确要求「至少一种方式看循环是否活着」） |
| A13 | 模型 / 推理档位 / token 预算**只**在 `host.toml` 配（`model_*` + `thinking_*` + `budget_implement_tokens`），循环不读 `~/.pi/agent/settings.json` 默认值；超预算 kill 并打回 `ready-for-agent` | AGENT 补（船长问「从哪里配」时暴露的空白） |
| A14 | Windows 宿主运行时 = **PowerShell 前门 + Git Bash 引擎**，绝不移植 pwsh 原生（脚本单一实现；Git Bash 自带 `flock`、`pi` Windows 可用均已实测） | OWNER（「平时就在 PowerShell 里跑 agent 任务」） |
