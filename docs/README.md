# LightKey 文档索引

轻钥 LightKey 的实施规格文档集。本文档是可**直接照此施工**的实现规格
（非 PRD），依据 2026-08-15 四轮 grilling 的 Wayfinder 决议集撰写；
全部决策已由船长逐条拍板，见 [`decisions.md`](decisions.md)。

## 文档约定

- **语言**：中文（团队工作语言）；标识符、命令、协议字段用英文。
- **状态**：本仓库内所有文档默认状态为 **已拍板（Approved）**——对应决议集内容
  不可自行变更；发现矛盾或需要新决策点时，走 needs-decision 上报，不擅改。
- **版本**：`V1 MVP`（2026-08 决议）。实现以 `docs/milestones.md` 的里程碑为准。
- **密文格式演进**：所有二进制/序列化格式均须自描述（含格式类型与版本号），
  为后续迁移留口。

## 文档地图

| 文档 | 内容 | 关联里程碑 |
|------|------|-----------|
| [decisions.md](decisions.md) | Wayfinder 决议集（拍板记录 + 映射） | 全部 |
| [architecture.md](architecture.md) | 总体架构、组件边界、技术栈、workspace | 全部 |
| [milestones.md](milestones.md) | M0–M3 里程碑范围与验收 | 全部 |
| [crypto.md](crypto.md) | 加密原语、KDF、密钥分叉、自描述密文格式 | M0 |
| [data-model.md](data-model.md) | 条目/附件/索引/墓碑、CAS、schema | M0 |
| [ipc.md](ipc.md) | 本地 IPC、守护进程、会话令牌 | M0 |
| [audit.md](audit.md) | 审计日志格式、HMAC 防篡改、保留策略 | M0 |
| [recovery.md](recovery.md) | 恢复码、恢复信封、已信任设备宽限 | M0 |
| [sync.md](sync.md) | BYO 同步、变更发现（轮询）、冲突收敛 | M1 |
| [authorization-gate.md](authorization-gate.md) | Agent 授权门三层模型、规则库、`lk inject` | M2 |
| [browser-fill.md](browser-fill.md) | 浏览器填充通道协议（Native Messaging） | M3 |
| [testing.md](testing.md) | 三层测试策略与 CI | 全部 |
| [cli.md](cli.md) | `lk` CLI 命令参考 | 全部 |
| [design/spec.md](design/spec.md) | 前端设计规范（tokens/组件/流程） | M2（界面） |
| [design/prototype](design/prototype/) | 高保真单页原型（可交互、可截图评审；含 M2.5 初始化向导） | M2/M2.5（界面） |

## 快速导航

- 想了解项目是什么 → [README](../README.md)
- 想动手写代码 → 先读 [milestones.md](milestones.md)（范围）、[architecture.md](architecture.md)
  （结构）、[testing.md](testing.md)（验收），再读对应功能规格。
- 想评审前端 → [design/spec.md](design/spec.md) + 原型预览说明。
- 遇到决策矛盾 → 对照 [decisions.md](decisions.md) 决议原文，仍矛盾则上报 needs-decision。
