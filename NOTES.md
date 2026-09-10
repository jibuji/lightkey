# NOTES — 我的工作环境（loop-me 原始记录）

工具、通道、我自己的用词。事实于 2026-09 由 agent 实测，非用户口述的条目都标 `#fact`。

## 通道 / 工具

- **Issue tracker**: GitHub Issues `github.com/jibuji/lightkey`，`gh` CLI 操作
  （见 `docs/agents/issue-tracker.md`）。**PR 不作为请求面**（no）。
- `#fact` `gh auth status`（2026-09-09 复核）：账号 `jibuji`，token scopes
  `manage_runners:org` + `read:org` + `repo` + `workflow`（早先缺 `read:org` 已补；
  判 OWNER 仍优先靠 `authorAssociation` 字段，不依赖 org 查询）。
- `#fact`（2026-09-09 实测）GITHUB_TOKEN 在 workflow 里**调不动** actions
  variables REST（`actions.getRepoVariable`，即便 `permissions.actions: read`
  也是 403 被 catch 吞）→ 仓库 Variable 必须经 runner `vars` 上下文注入
  （PR #185）。
- `#fact` CI：唯一 workflow `.github/workflows/release.yml`，
  `pull_request`（opened/synchronize/reopened）为门禁触发面；
  不自动合并、不推 main（交付纪律：功能分支 + PR + CI 全绿）。
- **执行 agent**: `pi`（本机已装）。`#fact` 非交互 `-p` 模式不弹 trust 提示，
  默认 `defaultProjectTrust=ask` 会**忽略项目资源**（AGENTS.md/skills 不生效），
  需显式 `--approve`/`-a` 或预先 `/trust`。

## 标签现状（issue tracker 实际）

`#fact` 已存在：`bug` `enhancement` `documentation` `duplicate` `question`
`invalid` `wontfix` `help wanted` `good first issue` `accessibility`
`needs-triage` `needs-info` `ready-for-agent` `ready-for-human`。
→ /triage 的五状态标签映射见 `docs/agents/triage-labels.md`。

## 验证能力（本机 = Linux 容器，决定哪些 issue 可委派）

- 可本机验证：`cargo test` / `cargo fmt --check` / `cargo clippy -D warnings`
  （lk-core / lk-daemon / lk-cli）、前端 `npm test`（vitest）、
  `scripts/e2e_m0.sh` / `e2e_m1.sh` / `e2e_m2.sh`（`file://` 模拟存储，无需凭据）。
- **不可**本机验证：Tauri 桌面壳 lk-app（无 webkit2gtk；Windows 交叉需
  conda env `lightkey-mingw`）、Windows/Linux 桌面产物、`e2e_cross_subsystem.sh`
  （需 WSL2 + Windows 桌面包；前置不满足会 SKIP exit 0）。
- 故「CI 绿」是本仓库唯一的完整门禁（CI 在 Windows runner 上跑三 crate + 前端）。

## Windows 宿主事实

- OWNER 日常前门 = **PowerShell**（工作习惯，agent 任务都在里面跑）。
- `#fact`（OWNER 实测回传）Git Bash 可用：`bash -lc 'command -v flock'` →
  `/usr/bin/flock`；`pi` 在该机已用过。Git Bash 里看到的 `cargo`/`node` 即
  Windows 原生工具链。

## 本机宿主事实（pi 非交互相关）

- `#fact` 嵌套 `pi -p` 用**默认 provider 会 401**（继承到的 `OPENAI_API_KEY` 无效）；
  必须显式 `--provider bailian-plan-personal --model …`。实测可用。
- `#fact` `/skill:<name>` 在 `-p` 打印模式下**会展开**（`--mode json` 流里可见 skill 正文），
  所以无人值守可以直接 `pi -p "/skill:implement …"`（`implement`/`triage` 都是
  `disable-model-invocation: true`，只能靠 slash 显式调用）。
- `#fact` 会话日志：`~/.pi/agent/sessions/<slug>/<ts>_<uuid>.jsonl`；`--session-dir` 可指定。
- `#fact` 主仓 `target/` 已 6.9 GiB；`git worktree list` 当前只有主仓。

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
