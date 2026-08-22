# 里程碑（M0–M3）

- 状态：已拍板（D3）；M1.5 插件化改造为船长插件化定案新增（已落地，见 §M1.5）
- 实现顺序严格执行；每个里程碑有明确出口标准，完成后按 [testing.md](testing.md)
  验收并交付。
- 关联：[plugin-architecture.md](plugin-architecture.md)（M1.5 起）·
  [architecture.md](architecture.md)（边界）· [decisions.md](decisions.md)（决议）

## 编号说明（2026-08 插件化定案）

- M0（单机闭环）、M1（同步）**已完成，现状不重写**。
- 新增 **M1.5 —— 插件化改造**，插入 M1 之后、M2 之前。
- **M2 / M3 标签保持不变**：M2 = Agent 授权门 + 桌面端（在插件化骨架上），
  M3 = 浏览器填充（V1 之后）。此编号方案避免波及其它文档的 M2/M3 引用，
  并已落地（M1.5 独立里程碑已完成）。

## M0 —— 骨架 + 单机闭环（已完成）

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
脚本走通单机闭环；Windows 冒烟通过。

## M1 —— 同步（BYO 变更发现 + CAS + 墓碑）（已完成）

**目标**：两个客户端通过 BYO 存储（WebDAV / S3 无服务器）最终一致。

范围：

- 存储端零知识布局（密文文件，文件名纯 UUID 无时间戳，见 [data-model.md](data-model.md)）
- 加密索引 + 轮询变更发现（默认 60s，可配 15s~3600s（1h）），静默、无中间态加载
- CAS 上传 + 冲突收敛（last-write-wins）+ 墓碑同步与 30 天延迟硬删
- `lk sync` / `lk config` 同步配置（[cli.md](cli.md)）

**出口**：E2E 双客户端冲突合并用例通过（见 [testing.md](testing.md)）；轮询代价
在 [sync.md](sync.md) 中如实记录。

## M1.5 —— 插件化改造（Cordis）（已完成）

**目标**：按 [plugin-architecture.md](plugin-architecture.md) 落地插件化架构——
Rust 核心按 A/B 层边界重组（trait 服务 + 事件总线，**行为不回归**），D 层 TS 用
真 Cordis 搭建宿主 + 首批插件（theme + ipc-bridge + preference-store + ui 骨架），
并落地槽位机制 + `cordis.yml` 装配。

范围：

- Rust 核心（`lk-core`）按 A/B 层边界重组：crypto / vault-store / recovery / audit /
  session（A 层）+ storage-backend / sync-engine（B 层）→ trait 服务 + 事件总线
  （模拟 Cordis 语义，见 plugin-architecture.md §3/§5）。
- C 层 daemon 宿主：装配 A/B、IPC 路由、空闲自动锁定、config.json 读写
  （现有 daemon 模块按此边界整理，行为不变）。
- D 层 TS：引入真 Cordis（`@cordisjs/core` 4.x）+ `cordis.yml` + loader +
  `@cordisjs/schema`；首批插件 theme + ipc-bridge + preference-store；React 宿主
  薄层（三栏骨架 + 槽位挂载 + 事件重渲染）。
- 槽位机制：`topbar`/`sidebar`/`content` 固定骨架 + 组件 `slot` 声明 + 布局数据。
- 事件总线契约落地：`item.changed` / `session.unlocked` / `session.locked` /
  `theme.changed` / `clipboard.copied`（`authz.request` 留待 M2 随 authz-gate 接入）。

**出口**：

- **行为不回归**：现有 M0/M1 全量测试（[testing.md](testing.md) 第一层 + E2E
  双客户端脚本 `scripts/e2e_m1.sh` / `scripts/e2e_m0.sh`）在重组后全绿；密文格式、
  存储布局、IPC 协议零变更（旧库可无损解锁）。
- D 层宿主可用：`cordis.yml` 装配首批插件 + 槽位骨架渲染，theme 暗/浅切换与
  偏好持久化（preference-store）走通，ipc-bridge 的 mock 适配器在无 Tauri 环境
  可跑通 ui 骨架。
- 事件总线：`item.changed` 三方响应、`session.unlocked/locked` 切换、`theme.changed`
  重渲染、`clipboard.copied` Toast + 30s 清除，均有单测/属性测试覆盖。

> 本里程碑已作为独立里程碑落地（编号 M1.5，见 [plugin-architecture.md](plugin-architecture.md) §10.1）。

## M2 —— Agent 授权门 + 桌面端（已完成）

**目标**：`lk inject` 三层授权可用；桌面应用完整可用（在 M1.5 插件化骨架上实现）。

范围：

- 授权门三层模型 + 启动者判定 + 规则库（`lk rule add` + 桌面规则管理页，
  见 [authorization-gate.md](authorization-gate.md)）——落在 authz-gate 插件（B 层）。
- 审批通道接口化（本地实现；远程留接口，P1 不做）——approval 插件（D 层）
  弹窗 + 30s 倒计时；`authz.request` 事件接入（plugin-architecture.md §5）。
- Tauri 壳接入：窗口、IPC 桥、解锁/锁定联动、审批弹窗、托盘——desktop-shell 插件。
- React 前端按 [design/spec.md](design/spec.md) 实现（解锁/条目/规则/设置/审计）——
  在骨架上实现 ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit 插件。
- 主题（theme 插件）与设计 tokens 接入实际界面；锁屏/超时自动锁定。

**出口**：授权门安全专项用例通过（绕过尝试、审计篡改检测）；Windows 验收；
M1.5 行为不回归仍保持（插件化骨架上新增功能不破坏既有闭环）。

## M2.5 —— 首次初始化向导（已完成）

**目标**：全新安装的桌面端首次启动进入初始化向导（而非直接显示解锁页）：
设主密码 → 展示恢复码（仅一次）→ 完成并解锁进入主界面。

范围：

- 首启检测：`vault.status` 新增 `initialized`（库是否已初始化）——Tauri 壳
  启动时先查库状态：无库 → 初始化向导；有库 → 正常解锁页（互斥门控）。
- 主密码策略留 Rust（安全核心不搬出）：`vault.init`/`vault.recover` 校验
  最小长度（至少 8 位，`vault.weak_password`）；弱密码/已存在库 UI 统一
  文案不区分（[ipc.md](ipc.md) §3 防探测语义）。
- 初始化向导（ui-onboarding 插件，忠实 [design/spec.md](design/spec.md)
  原型四步）：欢迎 → 设主密码（强度条 + 两次一致校验）→ 真实恢复码展示
  （仅 init 响应一次；勾选「我已保存」门控）→ 完成 unlock 进入主界面。
- 恢复码生成/信封/建库全部复用既有 `vault.init` 协议（[recovery.md](recovery.md)）。

**出口**：全新环境启动 → 向导（四步）→ 完成 → 已解锁主界面；有库环境
启动 → 解锁页（回归）；前端单测覆盖四步流（弱/强/不一致、checkbox 门控、
完成跳转）+ Rust 库状态检测单测（无库/有库）；`cargo test` + vitest +
clippy/fmt 全绿；agent_browser 跑通「首启→向导→完成→解锁」全流程。

## M3 —— 浏览器填充（V1 之后）

**目标**：浏览器扩展按 [browser-fill.md](browser-fill.md) 协议实现。

范围：

- Chrome 扩展（Native Messaging）+ 桌面已解锁会话取凭据填充——browser-fill 插件（D 层）。
- 填充置灰 + 快速解锁弹窗；剪贴板 30s 自动清除；只填充主动点击的输入框。

**出口**：扩展在桌面锁定/未运行时正确置灰；填充与剪贴板行为通过验收。
