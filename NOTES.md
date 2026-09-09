# NOTES — 我的工作环境（loop-me 原始记录）

工具、通道、我自己的用词。事实于 2026-09 由 agent 实测，非用户口述的条目都标 `#fact`。

## 通道 / 工具

- **Issue tracker**: GitHub Issues `github.com/jibuji/lightkey`，`gh` CLI 操作
  （见 `docs/agents/issue-tracker.md`）。**PR 不作为请求面**（no）。
- `#fact` `gh auth status`：账号 `jibuji`，token scopes `repo` + `workflow`，
  **缺 `read:org`**（影响：列 org 成员/判定 OWNER 之外的协作者要靠
  `authorAssociation` 字段，不能查 org 团队）。
- `#fact` CI：唯一 workflow `.github/workflows/release.yml`，
  `pull_request`（opened/synchronize/reopened）为门禁触发面；
  不自动合并、不推 main（交付纪律：功能分支 + PR + CI 全绿）。
- **执行 agent**: `pi`（本机已装）。`#fact` 非交互 `-p` 模式不弹 trust 提示，
  默认 `defaultProjectTrust=ask` 会**忽略项目资源**（AGENTS.md/skills 不生效），
  需显式 `--approve`/`-a` 或预先 `/trust`。

## 标签现状（issue tracker 实际）

`#fact` 已存在：`bug` `enhancement` `documentation` `duplicate` `question`
`invalid` `wontfix` `help wanted` `good first issue` `accessibility`
`needs-triage` `ready-for-agent` `ready-for-human`。
**尚不存在**：`needs-info`、任何「正在跑 / 已认领」状态标签、任何 `needs-human`。
→ /triage 的五状态标签映射见 `docs/agents/triage-labels.md`（映射表右列需补齐）。

## 验证能力（本机 = Linux 容器，决定哪些 issue 可委派）

- 可本机验证：`cargo test` / `cargo fmt --check` / `cargo clippy -D warnings`
  （lk-core / lk-daemon / lk-cli）、前端 `npm test`（vitest）、
  `scripts/e2e_m0.sh` / `e2e_m1.sh` / `e2e_m2.sh`（`file://` 模拟存储，无需凭据）。
- **不可**本机验证：Tauri 桌面壳 lk-app（无 webkit2gtk；Windows 交叉需
  conda env `lightkey-mingw`）、Windows/Linux 桌面产物、`e2e_cross_subsystem.sh`
  （需 WSL2 + Windows 桌面包；前置不满足会 SKIP exit 0）。
- 故「CI 绿」是本仓库唯一的完整门禁（CI 在 Windows runner 上跑三 crate + 前端）。

## Windows 宿主事实（autopilot 第二台宿主，2026-09-09 登记）

- OWNER 日常前门 = **PowerShell**（工作习惯，agent 任务都在里面跑）；autopilot 在
  Windows 侧的运行时钉死为「PowerShell 前门 + Git Bash 引擎」（A14）。
- `#fact`（OWNER 实测回传）Git Bash 引擎可用：`bash -lc 'command -v flock'` →
  `/usr/bin/flock`；`pi` 在该机已用过。
- 凭据未逐模型验（401 坑与平台无关），登记时按 workflows/issue-autopilot.md
  §13.4 逐模型验。
- 引擎选 Git Bash 而非 WSL 的理由：Git Bash 里看到的 `cargo`/`node` 即 Windows
  原生工具链，§7 探测如实反映 Windows 环境；WSL 引擎会把宿主退化成第二台
  Linux 机（`tauri-shell` 因缺 webkit2gtk 恒 false），§6 两机互补落空。

## 本机宿主事实（autopilot 相关）

- `#fact` 嵌套 `pi -p` 用**默认 provider 会 401**（继承到的 `OPENAI_API_KEY` 无效）；
  必须显式 `--provider bailian-plan-personal --model …`。实测可用。
- `#fact` `/skill:<name>` 在 `-p` 打印模式下**会展开**（`--mode json` 流里可见 skill 正文），
  所以无人值守可以直接 `pi -p "/skill:implement …"`（`implement`/`triage` 都是
  `disable-model-invocation: true`，只能靠 slash 显式调用）。
- `#fact` 会话日志：`~/.pi/agent/sessions/<slug>/<ts>_<uuid>.jsonl`；`--session-dir` 可指定。
- `#fact` 主仓 `target/` 已 6.9 GiB；`git worktree list` 当前只有主仓。
- `#fact` 现有 8 个 open issue 已带 `ready-for-agent`（#170–#177），其中 #173/#171/#175
  改动面含 `crates/lk-app`（本机无法编译验证）→ 能力词表与跳账机制的真实用例。

## 用词（已锐化，见 workflows/issue-autopilot.md §2）

- **跳账 (skipped-on-host)**：某宿主因能力不足跳过，只在 tracking issue 记账，
  **绝不改标签** —— 「本机做不了」是宿主属性，「需要哪些能力」才是 issue 属性。
- **NEEDS-HUMAN 评论协议**：用户在需求里造的词 —— agent 卡住时在 issue 上发一条
  以固定标记开头的评论 + 打 `needs-human` 标签；OWNER 回复后循环自动恢复。
  与 /triage 的 canonical `needs-info`（等**报告人**补信息）不是同一角色：
  前者等**维护者裁决**，后者等外部输入。待锐化。
- **pinned tracking issue 心跳**：状态面 = 标签（机器可读真相）+ 一个置顶
  tracking issue 上的人可读心跳/流水。细节待 grill。

## 看活（2026-09-09 补，回应「至少一种方式查看循环是否还活着」）

- **L1 外部见证** = `.github/workflows/autopilot-watchdog.yml`（GitHub 侧 `schedule`，
  每 30 分钟读 tracking issue 的 `last-ok:` 行，>45 分钟 → 打 `heartbeat-stale` + 评论一次）。
  **必须不在本机**：判定逻辑若也跑本机，机器关机时看门狗和病人一起倒。
- **L2 本机一眼** = `bash scripts/autopilot/status.sh`（退出码 0 活 / 1 可疑 / 2 坏了）；
  它同时检查 L1 自己的最近运行（>120 分钟没跑 = 看门狗可疑）。
- **心跳契约**：正文一行 `- last-ok: <ISO-8601 UTC>`；`poll.sh` 每轮**最先**写它。
  严格形状校验（`date -d ""` 返回今日零点、无时区串被 JS 按本地时区解析 = 两类
  「假装活着」的假象，已实测并堵掉）。

- `status.sh` verdict 四态：`ALIVE`(0) / `PAUSED`(0，人主动停) / `SUSPECT`(1) / `BROKEN`(2)；
  回归 12 例：`scripts/autopilot/tests/status.t.sh`（假 gh + 假 HOME，离线）。

## 模型 / 推理档位配置面（2026-09-09 实测）

- 交互层：`/model` + Ctrl+S、`/thinking` + Ctrl+S → 写 `~/.pi/agent/settings.json`
  （`defaultProvider` / `defaultModel` / `defaultThinkingLevel` /
  `modelThinkingLevels`（按 `provider/modelId` 钉启动档位）/ `thinkingBudgets`（每档 token 预算））；
  项目层 `.pi/settings.json` 覆盖全局（需 trust 才加载）。
- 单次层：`pi --provider <p> --model <id> --thinking <lvl>`，或后缀单参
  `--model <provider>/<id>:<lvl>`（实测 `qwen3.8-flash:high` 可用）。档位闭集
  `off|minimal|low|medium|high|xhigh|max`。
- **`PI_MODEL` / `PI_REASONING_LEVEL` 是输出不是输入**：pi 注入给子进程报告当前会话选型
  （本会话实测 = `bailian-plan-personal/qwen3.8-flash` + `reasoning=high`）。
- 验凭据：`pi auth check --provider <p> --model <m> --json` → `{"status":"ready","authType":"api_key"}`；
  枚举：`pi --list-models <关键词>`（本机可用：qwen3.8-flash 900K、qwen3.8-max 1M/128K out、
  deepseek-v4-pro、glm-5.2）。
- autopilot 层：只认 `host.toml` 的 `model_*` / `thinking_*` / `budget_implement_tokens`
  （spec §11.1），不读全局默认值。

## 启动层（2026-09-09 已落地：`scripts/autopilot/ctl.sh`）

- 船长定的实现档：`qwen3.8-flash` + `thinking=max`（分诊 flash+low）。
- 单实例的真相 = 内核 flock（`loop.lock` 常驻实例锁 / `poll.lock` 单轮锁），
  pid 文件仅人读提示；硬闸门在子进程 `flock -n`，父进程检查只为提示语。
- 回归 `scripts/autopilot/tests/ctl.t.sh` 18 例抓到两个真 bug：
  (1) 子进程继承持锁 fd → `fuser` 报一堆 PID → 看活层误判多实例（须 `9>&-`）；
  (2) `stop` 里删仍被人持有的锁文件 → 下个 start 能再起一个实例。
- 本机环境实测：pid1=systemd、`systemctl --user` 可用、cron 在跑、`flock`/`setsid`/`fuser` 齐备。
