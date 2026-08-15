# 里程碑（M0–M3）

- 状态：已拍板（D3）
- 实现顺序严格执行；每个里程碑有明确出口标准，完成后按 [testing.md](testing.md)
  验收并交付。

## M0 —— 骨架 + 单机闭环（当前阶段之后）

**目标**：不经任何网络，一个人在本机完成「建库 → 解锁 → 增删改查 → 锁定 →
恢复」的完整闭环，并产出本地审计。

范围：

- Rust workspace 骨架（已完成）+ `lk-core` 实现：
  - 加密原语与自描述密文格式（[crypto.md](crypto.md)）
  - 数据模型：条目 CRUD、加密索引、CAS、墓碑（[data-model.md](data-model.md)）
  - 解锁/锁定与会话（[ipc.md](ipc.md)）
  - 恢复信封（[recovery.md](recovery.md)）
  - 本地审计（[audit.md](audit.md)）
- CLI：`lk init` / `unlock` / `lock` / `item`（CRUD）/ `audit` / `daemon` / `status`（[cli.md](cli.md)）
- 守护进程解锁态 + 本地 IPC（JSON-RPC 2.0）可用。

**出口**：核心单元 + 属性测试过（加密往返、CAS 冲突、墓碑收敛）；CLI 端到端
脚本走通单机闭环；Windows + macOS 冒烟通过。

## M1 —— 同步（BYO 变更发现 + CAS + 墓碑）

**目标**：两个客户端通过 BYO 存储（WebDAV / S3 无服务器）最终一致。

范围：

- 存储端零知识布局（密文文件 + 文件名时间戳，见 [data-model.md](data-model.md)）
- 加密索引 + 轮询变更发现（默认 60s，可配 15s~24h），静默、无中间态加载
- CAS 上传 + 冲突收敛（last-write-wins）+ 墓碑同步与 30 天延迟硬删
- `lk sync` / `lk config` 同步配置（[cli.md](cli.md)）

**出口**：E2E 双客户端冲突合并用例通过（见 [testing.md](testing.md)）；轮询代价
在 [sync.md](sync.md) 中如实记录。

## M2 —— Agent 授权门 + 桌面端

**目标**：`lk inject` 三层授权可用；桌面应用完整可用。

范围：

- 授权门三层模型 + 启动者判定 + 规则库（`lk rule add` + 桌面规则管理页，
  见 [authorization-gate.md](authorization-gate.md)）
- 审批通道接口化（本地实现；远程留接口，P1 不做）
- Tauri 壳接入：窗口、IPC 桥、解锁/锁定联动、审批弹窗、托盘
- React 前端按 [design/spec.md](design/spec.md) 实现（解锁/条目/规则/设置/审计）
- 锁屏/超时自动锁定

**出口**：授权门安全专项用例通过（绕过尝试、审计篡改检测）；Windows + macOS
验收；Linux 冒烟。

## M3 —— 浏览器填充（V1 之后）

**目标**：浏览器扩展按 [browser-fill.md](browser-fill.md) 协议实现。

范围：

- Chrome 扩展（Native Messaging）+ 桌面已解锁会话取凭据填充
- 填充置灰 + 快速解锁弹窗；剪贴板 30s 自动清除；只填充主动点击的输入框

**出口**：扩展在桌面锁定/未运行时正确置灰；填充与剪贴板行为通过验收。
