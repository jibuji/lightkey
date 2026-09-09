/skill:implement

# 续跑任务（issue-autopilot 委派，run-id {{RUN_ID}}，attempt {{ATTEMPT}}/2，**续跑不重置**）

维护者已裁决。你之前的现场原样保留：分支、worktree、已做的一切。

## 维护者的裁决（原文注入，最高优先级）
{{AUTOPILOT_REPLY}}

## 现场（原样保留）
- worktree：`{{WORKTREE}}`（分支 `{{BRANCH}}`）
- 之前的进展与卡点：{{NEEDS_HUMAN_NOTE}}

## 目标 issue
#{{ISSUE_NUMBER}} {{ISSUE_TITLE}}

{{ISSUE_BODY}}

## 交付纪律
与上次相同：在 worktree 内继续实现 + 自测 → push `{{BRANCH}}` → 开/更新 PR（base main）。
PR 正文必填四段（`Closes #{{ISSUE_NUMBER}}` / Spec 依据 / 本机验证结果 / 护栏命中 /
NEEDS-HUMAN 历史——这次要写上卡过的那段与维护者怎么解的）。恰好一个提交。

## 禁令（安全不变量全文，逐条）
{{INVARIANTS}}

## 撞墙时
同上次：停手输出 `NEEDS-HUMAN: <一句话> | <单句问题>`，不要猜（§12.11）。
