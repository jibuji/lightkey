/skill:implement

# 实现任务（issue-autopilot 委派，run-id {{RUN_ID}}，attempt {{ATTEMPT}}/2）

## 现场（已备好）
- worktree：`{{WORKTREE}}`（分支 `{{BRANCH}}`，基于 origin/main；**在此工作，勿动主仓**）
- 本宿主可用能力：{{CAPABILITIES}}
- 本 issue brief：{{BRIEF}}

## 目标 issue
#{{ISSUE_NUMBER}} {{ISSUE_TITLE}}

{{ISSUE_BODY}}

## 交付纪律（必须遵守）
- 在 worktree 内实现 + 自测；**功能分支已建好**（`autopilot/{{ISSUE_NUMBER}}`），完成后
  push 该分支并开 PR（base main）。
- PR 正文**必填四段**（模板如下，如实填；「本机验证结果」写了什么就必须真的跑过什么）：

```
Closes #{{ISSUE_NUMBER}}

## Spec 依据
（docs/<spec>.md §<节> + issue brief 摘要）

## 本机验证结果
（跑了哪些命令、通过与否、缺哪个能力——如实写，CI 绿 ≠ 本机验证过）

## 护栏命中
（denylist 判定结果：干净 / 命中哪些路径）

## NEEDS-HUMAN 历史
（无 / 卡过哪、怎么解的）
```

- 恰好一个提交（后续 squash）：message 形如 `<type>(<scope>): <subject> (#{{ISSUE_NUMBER}})`。
- 本机验证命令见 AGENTS.md「常用命令」；能力不够验证的部分在「本机验证结果」里写明
  缺哪个能力，不要假装验证过。
- 任何测试 fixture 密钥不进仓库（docs/testing.md）。

## 禁令（安全不变量全文，逐条）
{{INVARIANTS}}

## 撞墙时
判定不了、缺权限、连续失败、护栏命中 → **停手**，在最终回复里输出：
`NEEDS-HUMAN: <一句话卡在哪> | <单句、可 Y-N 的问题>`——调度器会转 needs-human，
不要猜（§12.11）。
