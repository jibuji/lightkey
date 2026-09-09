# Triage Labels

The skills speak in terms of five canonical triage roles. This file maps those roles to the actual label strings used in this repo's issue tracker.

| Label in mattpocock/skills | Label in our tracker | Meaning                                  |
| -------------------------- | -------------------- | ---------------------------------------- |
| `needs-triage`             | `needs-triage`       | Maintainer needs to evaluate this issue  |
| `needs-info`               | `needs-info`         | Waiting on reporter for more information |
| `ready-for-agent`          | `ready-for-agent`    | Fully specified, ready for an AFK agent  |
| `ready-for-human`          | `ready-for-human`    | Requires human implementation            |
| `wontfix`                  | `wontfix`            | Will not be actioned                     |

When a skill mentions a role (e.g. "apply the AFK-ready triage label"), use the corresponding label string from this table.

Edit the right-hand column to match whatever vocabulary you actually use.

## 非分诊标签（autopilot 专属，`/triage` 不得读写）

| 标签 | 含义 | 谁能写 |
| ---- | ---- | ------ |
| `agent-working` | 已被某宿主认领、正在跑或有活动 PR | 循环调度器（`scripts/autopilot/poll.sh`） |
| `needs-human` | 等**维护者裁决**（≠ `needs-info` 的「等报告人补信息」） | 循环（恢复只能由人回复触发） |
| `heartbeat-stale` | 循环心跳失联（看活层信号，不代表任何 issue 状态） | `.github/workflows/autopilot-watchdog.yml` |

规格与状态机见 [../../workflows/issue-autopilot.md](../../workflows/issue-autopilot.md)（补充拍板 #29）。
