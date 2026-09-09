# issue-autopilot 机制评审与整改计划

- **日期**：2026-09-09
- **状态**：评审完成 · 计划待执行（本文只记录问题与计划，**不含代码改动**）
- **评审对象**：[`workflows/issue-autopilot.md`](../../workflows/issue-autopilot.md)（唯一出处）
  与其实现 `scripts/autopilot/**`、`.github/workflows/autopilot-watchdog.yml`
- **基线**：`main@cc89e20`（含评审期间合入的 #194 / #195）
- **证据**：线上实例（tracking issue #184、#171/#172/#173 时间线、systemd timer/journal、
  看门狗运行记录、`runs/*.jsonl`、`~/.local/state/lightkey-autopilot/poll.log`）
- **跟踪 issue**：[#203](https://github.com/jibuji/lightkey/issues/203)（子 issue #196–#202）

## 0. 结论

机制骨架成立（哑调度器 + 标签状态机 + 两层看活），但**状态机的写入点没有收敛**，
由此派生出三类系统性缺陷：**假占位/永久卡死**、**误伤并发人类活动**、**安全护栏不生效**。
评审期间最严重的 A1（假占位）已被 #195 修复；其余 P0 仍会在特定条件下把循环卡死或误伤。

## 1. 评审期间已修复（本文基线内）

| 编号 | 问题 | 修复 |
| --- | --- | --- |
| A1 | 认领先落 `agent-working`、配额/墙钟不足时空返回 → 假占位永久阻塞 | #195（`f6a6cab`）：`claim_phase` 前置配额/墙钟检查；`sweep` 兜底回收「有标签无戳」的认领 |
| A5（部分） | `gh pr create` 产生的 `refs/pull/*` 被误判为越界 | #194（`153eeff`）：ref 白名单放行 `refs/pull/` |

线上验证：`#173` 于 12:36:38Z 由 `agent-working` 退回 `ready-for-agent`；看门狗于
12:26:37Z 首次以 `schedule` 事件成功运行（此前 0 次，见 A12）。

## 2. 未修复问题

编号沿用本次评审；「根因」给当前基线的文件:行。

### P0 — 会导致卡死 / 误伤 / 护栏失效

#### A2 带戳的泄漏仍无法回收（回收路径不可达）

- **现象**：某 issue 认领后子进程死亡、无 PR，`sweep` 正确判为泄漏并设 `RECLAIM_CANDIDATE`，
  但该 issue 的 `agent-working` 标签**未摘**。
- **根因**：`poll.sh:235` 只设候选不摘标签；`claim_phase` 的 inflight 门在
  `poll.sh:529`（读 `agent-working` 计数）先 `return 0`，而 `RECLAIM_CANDIDATE`
  在 `poll.sh:542` 才被读 —— 候选本身必带 `agent-working`，门永远挡住回收。
- **影响**：§4 步骤 2 的「重试」整条分支从未生效；带戳泄漏 = 循环永久停摆。
  （#195 只修了「无戳」那半，带戳那半仍在。）
- **修复方向**：回收时即摘标签（或把候选从 inflight 计数中排除）；inflight 判据改为
  「有活 claim / 活子进程」而非标签本身。
- **回归**：假 gh 驱动 —— 一个带戳、无 PR、心跳超时的 issue，下一轮必须回到
  `ready-for-agent` 或 `needs-human`，且**不得**阻塞其他 issue 认领。

#### A3 PR CI 红永远检测不到

- **现象**：`gh pr checks --json state` 的取值是大写 `FAILURE`/`SUCCESS`（实测 PR #192），
  代码用 `[[ "$states" == *fail* ]]` 匹配小写。
- **根因**：`poll.sh:219-220`。
- **影响**：PR CI 失败的 issue 永远停在 `agent-working`（并因此触发 A2 的永久阻塞）。
- **修复方向**：按闭集匹配 `FAILURE|CANCELLED|TIMED_OUT|STARTUP_FAILURE|ACTION_REQUIRED|STALE`。
- **回归**：假 `gh pr checks` 输出 `FAILURE` → 必须判泄漏。

#### A4 attempt 永不递增 → §11「每 issue 自动重试 2」形同虚设

- **现象**：attempt 1 失败 → 打回 `ready-for-agent` → 下轮读到**同一个** `attempt=1`
  → 再失败，跨天无限重试（仅受每日配额约束）。
- **根因**：`claim_phase` 在 `poll.sh:577` 把读到的 attempt 原样传入；唯一 `+1` 的地方是
  不可达的 `poll.sh:543-544`（见 A2）。
- **修复方向**：认领时 `attempt+1` 并写入戳；attempt 到顶即 `needs-human`。
- **回归**：连续两次失败后必须进 `needs-human`，不再自动重试。

#### A5（残余）ref 白名单用「全局 before/after 差集」归因

- **现象**：`#171`/`#172` 被停成 `needs-human`，但两个 PR（#192/#193）CI 全绿。被判「越界」的
  是 `refs/heads/main`、`fix/autopilot-refs-whitelist`（人类刚推的）、`refs/pull/193|194/*`
  （其他轮次）—— 全是**别人**的正常活动。
- **根因**：`poll.sh:468` 对比整轮前后的 `git ls-remote` 全量 ref；`lib/pr.sh:65` 的
  `ap_refs_violations` 无法区分「谁推的」。`#194` 只放行了 `refs/pull/*`，`main`/他人分支仍在。
- **影响**：护栏反向伤害（该停的没停、不该停的停了）；且**不阻断**，只在事后归罪
  —— `v*` tag 触发 release 发生在检查之前。
- **修复方向**（三层，详见 `docs/decisions.md` #32）：
  1. **服务端（唯一不可绕过）**：`main` ruleset（禁 direct/force/删除 + 必需检查）、
     `v*` tag ruleset、token 最小化（不给 `workflow`）。当前实测 main **无保护、无 ruleset、
     无 tag 保护**。
  2. **推送时（精确归因）**：worktree 注入 `pre-push` hook（`core.hooksPath` 指向 state dir，
     防工作区篡改），只放行 `refs/heads/autopilot/<n>`；注意 `--no-verify` 可绕过，故它是
     tripwire。
  3. **事后审计**：hook 落实际 refspec 审计；事后只查「审计里出现的、白名单外的 ref」。
- **回归**：模拟「同窗口内他人推 main / 他人分支 / 新建 PR」→ 不得判违规；
  模拟 agent 推 tag / 他人分支 → 必须拦截。

#### A6 标签越权回滚是坏的 → §5 安全不变量不成立

- **现象**：分诊 agent 若写 `wontfix`，代码闸门的「回滚」只删掉首字符后的标签名
  （`needs-triage` → `eeds-triage`），**`wontfix` 原样留在 issue 上**。
- **根因**：`poll.sh:347` 遍历 `labels_after` 却用 `"${l:1}"`（本意是剥 diff 行的 `+`/`-`）。
- **修复方向**：按 `ap_label_diff` 的 `+`/`-` 行精确撤销新增、补齐删除。
- **回归**：假 gh 记录标签调用 → 越权标签最终不残留。

#### A7 agent 的 `NEEDS-HUMAN:` 终局回复无人解析

- **现象**：`prompts/implement.md:46`、`resume.md:28` 要求 agent 撞墙时输出
  `NEEDS-HUMAN: … | …` 并承诺「调度器会转 needs-human」，但全仓无解析。
- **根因**：`poll.sh` 只按 `AP_RC` 与「有无 PR」处置，从不读 `AP_OUT` 的终局文本。
- **影响**：agent 说「我卡住了、需要你决定 X」→ 被当成普通失败重试（烧配额），
  卡点与证据丢失，与 §8 协议断裂。
- **修复方向**：从 `runs/<n>/*.jsonl` 尾部抽该行 → 走 `post_needs_human` 并带原文。
- **回归**：假 pi 输出含 `NEEDS-HUMAN:` → 必须进 `needs-human` 且评论含原文。

#### A20（评审新增，已实测）· 服务端无 required status checks → `gh pr merge --auto` 不等待 CI

- **现象**：PR #193 在 CI 运行开始 **18 秒后**即被 squash 合并（`mergedAt=12:44:13Z`，
  对应 run `created=12:43:55Z` 且仍在 `in_progress`）。`main` 无 branch protection
  （API 404）、无 rulesets（`[]`），因此**没有任何 required status checks**；
  `gh pr merge --auto` 在「无必需检查」的仓库里只要 PR 可合并就立即合并。
- **影响**：交付纪律与 autopilot 的核心承诺「CI 全绿即自动合并」**并未被服务端强制** ——
  自动合并实际是「PR 可合并即合并」。一个 CI 未跑完/会变红的 autopilot PR 可以先
  进 `main`（denylist 仍拦，但 CI 不拦）。
- **修复方向**：`main` ruleset 配置 required status checks（三个 build job）+ 要求分支最新；
  这是决策 #32 第 1 层（服务端）的一部分。
- **回归**：配置后，CI 未完成时 `gh pr merge --auto` 必须**挂起**而非合并（人工验证一次）。

### P1 — 静默失败 / 可观测性 / 并发

- **A8 `restore_phase` 不检查 inflight**（`poll.sh:368-397` 与 `:529`）：存在遗留
  `agent-working` 时会起第二个 implement，打破「并发=1」。修复：恢复路径复用同一 inflight 门。
- **A9 timer 模式下轮次日志几乎为空**：`lib/common.sh:53` 仅在 stderr 是 tty 时写 `poll.log`；
  systemd 下日志进 journal，而 `status.sh`「轮次日志尾」与 `ctl tail` 读 `poll.log`
  （实测该文件只有探针 warning）。另探针 stderr 每轮追加且无轮转。修复：统一落盘 + 轮转，
  或让 `status.sh` 读 journal。
- **A10 auto-merge 失败被误归因且不升级**：`lib/pr.sh:141` 的 `gh pr merge --auto && ap_log`
  失败时函数返回 1，`poll.sh:488-495` 把它显示成「缺 Closes 行」，两种情况都保留
  `agent-working` 不升级。修复：区分退出码/错误文本，失败即 `needs-human`。
- **A11 孤儿 pi 子进程**：`lib/pi-run.sh:70` 用 `setsid` 起子进程（预算按组杀所需），但
  `ctl.sh:67/124` 的 `timeout` 只杀到 poll 进程组，setsid 子进程逃逸后仍可 push/评论；
  `sweep` 只回收 `agent-working` issue，**triage 孤儿永不回收**。修复：poll 退出 trap +
  启动时按 `runs/*/child.pid` 清理孤儿。
- **A12 心跳阈值 < 轮次上限 + L1 调度曾长期缺席**：`lib/heartbeat.sh:13` 阈值 45m，而单轮
  墙钟上限 60m，长轮次中途会被误报失联；看门狗此前 **schedule 0 次**（07:26Z 上线至
  12:26Z 才首次触发）。修复：长轮次中途刷新 `last-ok` 或阈值抬到 > 轮次上限 + 间隔；
  `status.sh` 区分 schedule / dispatch（手工 dispatch 会掩盖 schedule 停摆）。

### P2 — 健壮性 / 范围

- **A13 探测无总预算**：`probe-capabilities.sh` 最坏 ~1.5h（`cargo test` 1800s + 两次
  `cargo check` 1800s + `npm test` 900s + e2e 前置 300s），可超过 60m 轮次墙钟；每轮重复付。
  修复：缓存 + 总预算。
- **A14 ref 白名单正则未锚定 + 删除不检测**：`lib/pr.sh:66` 的 `autopilot/[0-9]+$` 会放行
  `refs/heads/evil/autopilot/5`（已实测）；`git push --delete` 不在「新/变 ref」里。
- **A15 可预测临时文件名**：`lib/labels.sh:120-121` 用 `/tmp/.ap_lbl_a.$$`，应 `mktemp`。
- **A16 provider 全阶段共用**：`lib/pi-run.sh` 的 `ap_pi_flags` 只取一个 `provider`，
  §11.1 的「每阶段模型」无法分 provider（`host.toml` 已自注此坑）。
- **A17 §11.1 可复现记录不全**：model/thinking/usage 只进 `runs/*.jsonl` 首行，心跳「本轮」区缺失。
- **A18 杂项**：`quota-<date>.json` 实为文本；`ap_comment_edit` 每次重复 `gh repo view`；
  人工抢单打 `ready-for-human` 无规格依据；`ap_triage_whitelisted` 收了规格外的 `question`；
  `probe` 的 `"ok":true` 恒真（全 false 时也 true）。

### A19（评审新增，待拍板）· `scripts/autopilot/**` 不在 denylist，且 CI 不跑其测试

- **现象**：`lib/pr.sh:25-48` 的路径闭集不含 `scripts/autopilot/**`；`.github/workflows/release.yml`
  也不跑 `scripts/autopilot/tests/*.t.sh`（实测 grep 无命中）。
- **影响**：agent 可以修改**自己身上的护栏**（`poll.sh`/`pr.sh`/`labels.sh`），CI 全绿即自动
  合并，而 CI 根本没验过这些脚本 —— 正是 §10 denylist 声称要挡的「CI 绿覆盖不到」那一类。
  评审期间 #194/#195 改的正是这些文件（人工作业，未走自动合并）。
- **修复方向**：① `scripts/autopilot/**` 补入 denylist 闭集；② 把三个 `.t.sh` 纳入 CI 门禁
  （零额外依赖、离线可跑）。二者独立，可分别落地。
- **状态**：需 OWNER 拍板（改动 denylist = 改 agent 的合并权限出处）。

## 3. 两轴小结

### Standards 轴

- **硬违反**：`poll.sh` 头部与 §4 承诺「任何阶段失败都要非 0 退出…**禁止静默**」，
  A9/A10 均为静默或误导；§12 第 1/7 条「越界即回滚」因 A6 不成立。
- **回归假绿**：`poll.t.sh`/`ctl.t.sh`/`status.t.sh` 共 87 例全绿，但 **0 例覆盖**
  A1–A8 这类状态机迁移（测试钉的是纯函数）。
- **smell（judgement call）**：Divergent Change / Long Function（`poll.sh` 近 580 行承担
  回收+降级+分诊+恢复+认领+实现+PR+心跳）；Duplicated Code（`gh issue list … @tsv | sort` +
  `ap_comments_tsv` 在 5 处重复）；Primitive Obsession（标签名、attempt、状态裸字符串跨层传）；
  Feature Envy（`labels.sh` 的 `ap_ready_since` 直连 GitHub timeline API）；死代码/怪名
  （不可达的回收路径、未被读的 `RECLAIM_WHY`、`local_iv`）；可移植性（`df -BG --output` 为 GNU 专有）。

### Spec 轴

| spec 条款 | 状态 |
| --- | --- |
| §4 步骤 2 泄漏回收/重试 | 实现但不可达（A2），CI 红判据错误（A3） |
| §5 分诊越权回滚 | 未达成（A6） |
| §6 认领资格/配额 | 资格过滤在；配额前置已由 #195 补上（A1 已修） |
| §8 NEEDS-HUMAN 协议 | 锚点/恢复判定正确；agent 主动撞墙不升级（A7） |
| §10 ref 白名单 + auto-merge | 归因语义错（A5）、失败处理错（A10） |
| §11 重试 2 / 超时杀子进程 | 未达成（A4 / A11） |
| §11.1 心跳可复现记录 | 缺失（A17） |
| §9.1 L1 外部见证 | 代码在；schedule 长期缺席后已恢复（A12） |
| 范围外 | `question` 白名单、人工抢单打 `ready-for-human`、`ok:true` 恒真 |

## 4. 整改计划

### Phase 0 · 已执行 / 立即

- 已由 OWNER 合入 #194（refs/pull）、#195（认领槽）。
- **已完成**：被误伤的 #171/#172 已人工处置 —— PR #192 合入；#193 与 #192 冲突，已在
  `autopilot/172` 上 rebase 解冲突（152 tests + `tsc --noEmit` 绿）后合入；两 issue 关闭、
  `needs-human` 摘除、分支/worktree 清理。
- **已完成**：模型 ID `-expires-on-0910` 换为 `deepseek-v4-flash`（`host.toml`，凭据已验 ready）。
- **新发现 A20**（合并 #193 时实测）：服务端无 required status checks，`--auto` 不等 CI。

### Phase 1 · P0 代码修复（每项独立 PR + 离线回归）

1. **状态机收敛**（A2/A8，issue #196）：新增 `ap_claim`/`ap_release` 单一迁移函数；所有前置检查在任何
   标签写入之前；失败必回滚；inflight 判据改用活 claim/活子进程；回收即释放标签。
2. **泄漏判定改用子进程活性**（A2/A11，issue #196）：`child.pid` + `kill -0` 为第一判据，时间戳兜底。
3. **attempt 计数**（A4，issue #198）：认领时递增并写入戳。
4. **CI 状态判据**（A3，issue #197）：大写闭集匹配。
5. **ref 护栏重做**（A5/A14，issue #199）：服务端保护 + 推送时 hook + 事后审计（决策 #32）；
   其中服务端部分含 A20（required status checks，issue #205）。
6. **标签回滚**（A6，issue #200）：按 diff 精确撤销/补齐。
7. **NEEDS-HUMAN 升级**（A7，issue #201）：解析 agent 终局输出。
8. **A19**（issue #202）：`scripts/autopilot/**` 入 denylist + 三个 `.t.sh` 入 CI（待拍板）。

### Phase 2 · P1 收敛

日志落盘 + 轮转（A9）；auto-merge 失败归因与升级（A10）；缺 `Closes` 升级（A10）；
孤儿进程回收（A11）；心跳阈值/中途刷新 + `status.sh` 区分 schedule/dispatch（A12）。

### Phase 3 · 配置 / 健壮性

探测缓存与预算（A13）；`mktemp`（A15）；provider 分阶段或文档写明限制（A16）；
心跳补 model/thinking/usage（A17）；杂项（A18）。

### Phase 4 · 验收（加厚 spec §15 DoD）

- 每个 P0 都有假 gh 驱动的**状态机回归**：配额尽不产生假占位、CI FAILURE 必回收、
  并发 push 不误伤、禁标签越权必回滚、agent 输出 NEEDS-HUMAN 必升级、孤儿子进程必回收。
- 真实环境：`DRY_RUN=1` 一轮 → 玩具 issue 端到端 → 三条中断（`[PAUSED]`、`mine` 抢单、
  NEEDS-HUMAN 续跑）。
- 新增两条 DoD：**「人类并发 push 不误伤」**、**「带戳泄漏必回收」**。

## 5. 决策登记

本计划涉及的规格修订已登记为 [`docs/decisions.md`](../decisions.md) 补充拍板 #31–#33；
A19 待拍板。规格唯一出处 `workflows/issue-autopilot.md` 的对应条款在决策生效后同步修订。
