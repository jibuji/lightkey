/skill:triage

# 分诊任务（issue-autopilot 委派）

## 目标 issue
#{{ISSUE_NUMBER}} {{ISSUE_TITLE}}

{{ISSUE_BODY}}

## 输出要求
按 triage 纪律分诊：Triage Notes 评论 + 状态/类别标签 + agent brief（含 `Needs:` 行）。
`Needs:` 只能从能力闭集取词：`rust-workspace`、`frontend-vitest`、`tauri-shell`、
`windows-cross-check`、`wsl2-desktop-e2e`、`release-build`——**绝不写机器名/宿主名**
（需求是 issue 的固有属性，"我做不了"是宿主的属性）。
不可本机验证的活要在这里就落 `ready-for-human` 并写明缺哪个能力，而不是留给实现阶段撞墙。

## 权限边界（硬约束，逐条）
- 允许读写：`needs-triage` `needs-info` `ready-for-agent` `ready-for-human` + 既有类别标签
  （`bug` `enhancement` `documentation` `question`）。
- **禁止**：`wontfix`、关闭 issue、标 `duplicate`、写 `.out-of-scope/`。
- **禁止**：读或写 `agent-working` / `needs-human`（autopilot 专属，只有调度器能写）。
- **禁止**：修改别人的评论、改 milestone / assignee。
- 任何「终结性」判定（拒绝与判死）是维护者的价值判断，你没有这个权重。

## 禁令（安全不变量全文）
{{INVARIANTS}}

{{DRY_RUN_BLOCK}}
