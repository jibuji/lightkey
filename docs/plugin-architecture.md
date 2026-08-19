# 插件化架构规格（plugin-architecture）

- 状态：已拍板（船长插件化定案，2026-08；落地层 = 选项 A；对应决议集映射待补，见 §9）
- 关联：[architecture.md](architecture.md)（边界纪律）· [milestones.md](milestones.md)
  （M1.5 插件化改造）· [decisions.md](decisions.md)（决议集——本定案尚未登记，见 §9）
  · [design/spec.md](design/spec.md)（tokens/组件/槽位落点）· [ipc.md](ipc.md)（跨进程桥）

> 本文档是纯设计规格，只改 docs/；插件化改造是**边界重组 + 声明式装配**，
> **不改变既有安全模型、密文格式、存储布局**（行为不回归，见 [milestones.md](milestones.md) M1.5 出口）。

## 1. 目标与原则

### 1.1 落地层（选项 A，船长定案）

| 层 | 技术 | 说明 |
|----|------|------|
| TS/桌面/前端（D 层） | **真 Cordis**（`@cordisjs/core` 4.x） | 插件框架 |
| Rust 核心（A/B 层） | **单一 crate `lk-core`**，按同一套插件边界重组模块 | trait 服务 + 事件总线**模拟** Cordis 语义，不强行移植 Cordis |
| 安全核心（加密/数据/同步/审计） | 留在 Rust | 不重写为 TS |
| CLI / Tauri 壳（C 层宿主 + 壳） | 只做编排与呈现 | 不复制业务逻辑 |

### 1.2 边界纪律（沿用 [architecture.md](architecture.md) §3，不放松）

- `lk-core` 仍是**唯一**包含业务逻辑的库；插件化只是把它的模块按 A/B 边界重组，
  不把逻辑外溢到 CLI / 桌面壳 / 前端。
- 密钥等敏感内存仅在守护进程（[ipc.md](ipc.md)）；前端不直接接触加密层。
- 插件化不改变：密文/自描述容器格式（[crypto.md](crypto.md)）、存储对象布局
  （[data-model.md](data-model.md) §2）、IPC 协议（[ipc.md](ipc.md) §2 的 JSON-RPC 2.0）。
- 事件总线是**新增的解耦层**，不替代 IPC（见 §4.2）。

### 1.3 三条「不」

1. **不把安全核心搬出 Rust**（加密/数据/同步/审计永远在 A/B 层）。
2. **不把 UI 布局/像素交给 Cordis**（Cordis 不管 React/布局，UI 需薄 React 宿主，见 §8）。
3. **不让应用数据包含逻辑**（条件/循环/计算 = 该写组件/服务，防 inner-platform，见 §6）。

## 2. 术语（本文档约定）

| 术语 | 含义 |
|------|------|
| 插件（Service） | 有生命周期的服务单元。TS 侧 = Cordis Service（函数带 `inject`+`apply(ctx)` 或 Service 子类，以 `@cordisjs/core` 4.x 为准）；Rust 侧 = trait 服务 |
| 原子组件 | 强交互 React 组件（密码字段+眼睛+复制、Markdown 高亮、倒计时环形、附件进度），手写、注册进组件注册表，**不拆内部结构** |
| 槽位组件 | 挂入 `topbar`/`sidebar`/`content` 的组件（导航项、搜索框、同步状态点、页面），声明 `slot` 字段 |
| 应用数据 | 随应用发布的**声明式装配契约**（驱动组件/插件/事件路由），永不运行时可变、永不含逻辑 |
| 用户数据 | 保险库里的条目/密码/规则等加密数据，与应用数据严格分离 |

## 3. 四层插件清单

### 3.1 A 层 · 数据平面（Rust `lk-core`，安全核心）

| 插件 | 边界 | 能力 | 依赖 | 里程碑 |
|------|------|------|------|--------|
| crypto | 加密原语 | KDF 派生、AEAD 加解密、自描述密文格式 | 地基 | M0 |
| vault-store | 加密数据落盘 | 条目/索引/墓碑/附件 CRUD、CAS、30 天延迟硬删 | crypto | M0 |
| recovery | 恢复 | 恢复码、恢复信封、重加密轮换 | crypto + vault-store | M0 |
| audit | 审计 | 追加日志 + HMAC 防篡改 + 密钥轮换链 | crypto | M0 |
| session | 会话 | 令牌签发/校验/轮换 | — | M0 |

### 3.2 B 层 · 能力域（Rust `lk-core`，业务逻辑）

| 插件 | 边界 | 能力 | 依赖 | 里程碑 |
|------|------|------|------|--------|
| storage-backend | 存储适配 | WebDAV/S3/本地，统一读写接口 | —（可插拔） | M1 |
| sync-engine | 同步 | 变更发现、CAS 冲突收敛、墓碑同步 | vault-store + storage-backend | M1 |
| authz-gate | 授权门 | 三层模型、规则库、启动者判定 | session + audit | M2 |

### 3.3 C 层 · 宿主（Rust，现位于 `lk-cli` 的 daemon 模块）

| 插件 | 边界 | 能力 |
|------|------|------|
| daemon | 守护进程 | 装配 A/B 层、IPC 路由、空闲自动锁定、config.json 读写 |

### 3.4 D 层 · 桌面/前端（TS，真 Cordis）

| 插件 | 边界 | 能力 | 依赖 | 里程碑 |
|------|------|------|------|--------|
| ipc-bridge | 桥 | 统一 IPC 门面 + mock/tauri 适配器 | 地基 | M1.5（首批） |
| preference-store | 偏好存储 | 非敏感 UI 偏好落盘（localStorage/tauri store） | — | M1.5（首批） |
| theme | 主题 | 设计 tokens、暗/浅色切换、偏好持久化 | preference-store | M1.5（首批） |
| ui-onboarding | 初始化向导（首启） | 四步向导：欢迎/设主密码/恢复码展示/完成；首启门控（无库） | ipc-bridge | M2.5 |
| ui-unlock | 解锁页 | 密码/Windows Hello/恢复码入口 | ipc-bridge | M2 |
| ui-vault | 条目 | 列表/搜索/详情/编辑 | ipc-bridge | M2 |
| ui-rules | 规则 | 规则 CRUD | ipc-bridge | M2 |
| ui-settings | 设置 | 同步/安全/审计保留 + 主题选择 | ipc-bridge + theme | M2 |
| ui-audit | 审计 | 事件流只读展示 | ipc-bridge | M2 |
| desktop-shell | 壳 | 窗口/托盘/锁屏联动 | ipc-bridge | M2 |
| approval | 审批 | 弹窗 + 30s 倒计时 | ipc-bridge | M2 |
| browser-fill | 填充 | 原生消息 + 剪贴板 30s 清除 | ipc-bridge | M3 |

> 「地基」= 无上游依赖，其余插件可注入。M1.5 的首批插件为
> **theme + ipc-bridge + preference-store + ui 骨架（React 宿主 + 槽位 + 最小壳）**；
> 其余 D 层插件在 M2 桌面端于骨架之上实现（见 [milestones.md](milestones.md)）。
> M2.5 增 **ui-onboarding**（首启向导；与 ui-unlock 互斥——宿主锁态按
> `vault.status.initialized` 门控，无库→向导 / 有库→解锁页）。

## 4. 依赖图（inject 方向）

### 4.1 Rust（A/B/C，trait 服务注入）

```
地基（无依赖）
├─ crypto            （session 可直接用；其余经 vault-store/audit/recovery 间接）
├─ vault-store  ← crypto
├─ recovery     ← crypto + vault-store
├─ audit        ← crypto
├─ session      （无依赖）
└─ storage-backend （无依赖，可插拔：webdav/s3/local 三实现）

B 层
├─ sync-engine  ← vault-store + storage-backend
└─ authz-gate   ← session + audit            （M2）

C 层
└─ daemon：装配以上全部 A/B 插件 + IPC 路由 + 空闲自动锁定 + config.json 读写
```

- 注入方向 = 上层注入下层：`sync-engine` 注入 `vault-store` 与 `storage-backend`；
  `recovery` 注入 `crypto` 与 `vault-store`；`authz-gate` 注入 `session` 与 `audit`。
- `storage-backend` 的「可插拔」= trait 对象注入，三个实现（WebDAV/S3/本地）
  按配置选择，与 D 层 `ctx.isolate` 的「服务换实现」语义对应（但 Rust 侧是 trait 实现切换）。

### 4.2 TS（D 层，真 Cordis `inject`）

```
ipc-bridge      （地基）
preference-store（地基）
theme          ← preference-store
ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit
               ← ipc-bridge
ui-settings    ← ipc-bridge + theme
desktop-shell / approval / browser-fill  ← ipc-bridge
```

### 4.3 跨进程总览

```
┌──────────────────────── Rust（lk-core + lk-cli 宿主）─────────────────────────┐
│ C 层 宿主 daemon（lk-cli）：装配 A/B、IPC 路由、空闲自动锁定、config.json        │
│   ┌──────────────── B 层 能力域 ────────────────┐                            │
│   │ sync-engine ← vault-store                  │                            │
│   │ authz-gate(M2) ← session + audit           │                            │
│   │ storage-backend（webdav/s3/local 可插拔）    │                            │
│   └──────────────┬──────────────────────────────┘                            │
│   ┌──────────────┴──────────────────────────────┐                            │
│   │ A 层 数据平面：crypto · vault-store ·         │                            │
│   │             recovery · audit · session      │                            │
│   └─────────────────────────────────────────────┘                            │
└─────────────────────────────────┬────────────────────────────────────────────┘
                                  │ 本地 IPC（JSON-RPC 2.0，ipc.md 不变）
┌─────────────────────────────────┴────────────────────────────────────────────┐
│ D 层 桌面/前端（TS · 真 Cordis @cordisjs/core 4.x）                            │
│   React 宿主薄层（三栏骨架 + 槽位挂载 + 事件重渲染）                             │
│   ipc-bridge（统一 IPC 门面 + mock/tauri 适配器）                              │
│   theme ← preference-store                                                   │
│   ui-unlock / ui-vault / ui-rules / ui-settings / ui-audit /                 │
│   desktop-shell / approval / browser-fill  —— 均 ← ipc-bridge                │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 5. 事件总线契约（跨层解耦）

### 5.1 语义来源

- TS 侧（D 层）用 Cordis 事件：`emit`（观察广播，fire-and-forget）、
  `waterfall`（中间件短路，有返回值即可截断）、`parallel`（并行扇出，收集返回值）、
  `serial`（按序执行）。以 `@cordisjs/core` 4.x 为准。
- Rust 侧（A/B 层）**模拟同套语义**（trait 事件 + 分发器），不移植 Cordis。
- **跨进程**：Rust ↔ TS 之间的事件经 `ipc-bridge` 翻译（Rust 事件 → IPC 通知 →
  TS 侧重新 `emit`；TS 侧需 Rust 决策的事件 → IPC 请求/响应，见 §5.3）。

### 5.2 事件清单

| 事件 | 负载（最小字段，**无密钥值**） | 分发 | 监听者（层） |
|------|------------------------------|------|--------------|
| `item.changed` | `{ itemId, revisionDate, type, deleted }` | `emit` | sync-engine（B，推送上传）· audit（A，记录）· ui-vault（D，刷新） |
| `session.unlocked` | `{ via: password \| biometric \| recovery }` | `emit` | ui 各插件（D，切解锁态）· sync-engine（B，恢复轮询） |
| `session.locked` | `{ reason: manual \| timeout \| lockscreen \| daemon-exit }` | `emit` | ui 各插件（D，回解锁页）· sync-engine（B，暂停轮询） |
| `authz.request` | `{ requestId, starter, projectDir, command, keys[]（仅 key 名） }` | `emit`（Rust→TS） | approval（D，弹窗 + 30s 倒计时） |
| `theme.changed` | `{ theme: dark \| light }` | `emit` | 所有 ui 插件（D，重渲染） |
| `clipboard.copied` | `{ source, field, clearedAt }` | `emit` | Toast（D，提示）· 30s 清除计时（D） |

- `item.changed` = 一事件三方响应（sync 推送 / audit 记录 / ui 刷新）；三方互不依赖、
  无需返回值聚合，故用 `emit`；若未来需收集结果再换 `parallel`。
- 所有负载沿用 [ipc.md](ipc.md) §4 的**最小字段原则**：只含索引级元数据或 key 名，
  密钥值永不出守护进程、永不进事件负载。
- D 层内部事件（不跨进程，不进本表）：`vault.search` / `vault.search-enter`
  （topbar 搜索）与 `vault.initialized`（M2.5 首启门控：ipc-bridge 探测
  `vault.status` 后本地 emit，宿主据此在向导/解锁页间互斥切换）——
  契约见 `frontend/src/events.ts`。

### 5.3 跨进程方向与返回路径

| 场景 | 事件起点 | 终点 | 机制 |
|------|----------|------|------|
| 同步发现变更 / 会话切换 | Rust（sync-engine / session） | TS 各 ui 插件 | Rust 事件 → ipc-bridge → TS `emit` |
| 主题切换 / 剪贴板复制 | TS（theme / ui 组件） | TS 各 ui 插件 | TS 内 `emit`（不跨进程） |
| 授权审批 | Rust（authz-gate） | TS（approval 弹窗） | `authz.request` 通知弹窗；用户决定经 IPC 方法 `approval.result` **回传**（跨进程无同步事件返回值） |

- 授权门三层模型（默认拒绝 → 规则白名单 → 弹窗）本身是 **Rust 内部确定性流程**
  （`waterfall` 语义：命中即短路），硬编码在 authz-gate（B），不数据化（见 §7）。
  事件总线的 `authz.request` 只是「需要用户决策」的通知，决策权仍在 Rust 侧。

### 5.4 语义对照（框架能力如何落位）

| Cordis 语义 | 本项目的落点 |
|-------------|--------------|
| `emit`（观察广播） | 上述 6 个事件的默认分发；无返回值、互不阻塞 |
| `waterfall`（中间件短路） | Rust 侧授权门三层模型内部（默认拒绝/规则/审批，命中即返回）；安全流程，硬编码 |
| `parallel`（并行扇出） | 备选：`item.changed` 若需聚合三方结果时 |
| `serial`（按序） | 备选：锁定/卸载时的有序撤销（先停同步→擦密钥→失效令牌）；此为 Rust 内部确定性流程，硬编码，不靠事件总线保证顺序 |
| 可逆副作用（`ctx.effect()`/`ctx.on()`） | D 层插件注册监听时用；插件卸载自动撤销（如 theme 卸下时移除重渲染订阅） |
| 服务级替换/增强（`ctx.isolate`/`ctx.intercept`/`ctx.provide/set/get`） | D 层换插件实现/拦截配置的原生机制；对应 Rust 侧 trait 实现切换（storage-backend） |

## 6. 装配机制（四层）

| 层 | 问题 | 谁决定 | 机制 |
|----|------|--------|------|
| ① 存在 | 哪些插件存在 | 数据驱动 | `cordis.yml` + `@cordisjs/plugin-loader` |
| ② 位置 | 组件放哪、顺序 | 槽位 + 注册声明 | 宿主定义固定槽位（`topbar`/`sidebar`/`content`），组件声明 `slot` 字段挂入；槽位内顺序由布局数据决定 |
| ③ 数据源 | 组件读哪个服务 | 数据驱动 | `inject` 依赖声明（Cordis 自动排加载顺序） |
| ④ 内部 | 组件怎么画、展示哪些字段 | React 写死 | 强交互组件本体（见 §7） |

### 6.1 槽位清单

| 槽位 | 宿主写死（产品身份） | 数据驱动（插件增删/换实现的落点） | 挂入组件（示例） |
|------|----------------------|----------------------------------|------------------|
| `topbar` | 顶栏位置与样式 | 组件有无与顺序 | 搜索框、同步状态点、同步按钮 |
| `sidebar` | 三栏骨架、64px 图标栏、底部锁定位 | 导航项有无与顺序 | 条目/规则/设置/审计导航项、锁定按钮 |
| `content` | 内容区容器、路由骨架 | 页面插件挂载 | ui-vault / ui-rules / ui-settings / ui-audit |

- **槽位分界**：槽位骨架（三栏）→ 宿主写死；槽位内组件有无/顺序 → 数据驱动。
- **导航项本身也是组件**，注册到 `sidebar` 槽位即可新增导航。
- 强交互原子组件（密码遮罩/Markdown 高亮/倒计时环形/附件进度）**不占槽位**——
  它们是注册进组件注册表的 React 组件，被数据/页面插件引用。

### 6.2 `cordis.yml` 示例（示意）

```yaml
# cordis.yml —— 应用数据（随应用发布的声明式装配契约）
# 只描述「用哪个插件、怎么组合、传什么配置」；不含逻辑；运行时不可变。
# 字段名以 @cordisjs/plugin-loader 实际 schema 为准（本示例为示意）。

plugins:
  - name: ipc-bridge
  - name: preference-store
  - name: theme
    config:
      defaultTheme: dark          # 默认暗色；实际取值以 preference-store 为准
  - name: ui-vault
    slot: content
  - name: ui-rules
    slot: content
  - name: ui-settings
    slot: content
  - name: ui-audit
    slot: content
  - name: nav-vault                # 导航项 = 组件，注册到 sidebar 槽位
    slot: sidebar
    order: 1
  - name: nav-rules
    slot: sidebar
    order: 2
  - name: nav-settings
    slot: sidebar
    order: 3
  - name: nav-audit
    slot: sidebar
    order: 4
  - name: lock                     # 底部锁定按钮
    slot: sidebar
    order: 99
  - name: search
    slot: topbar
  - name: sync-status
    slot: topbar
```

- 无 `slot` 的插件（ipc-bridge / preference-store / theme）是**服务**，被其他插件
  `inject` 消费，不直接占槽位。
- 配置校验用 `@cordisjs/schema`；M1.5 起本文件随应用发布，M2/M3 新增插件即在
  此增删（数据驱动落点）。

## 7. 数据驱动边界（应用数据 vs 用户数据）

### 7.1 精确定义（船长原话）

- **数据驱动的最小单位是「强交互组件这个整体」**：如「密码字段+眼睛+复制」是一个
  原子组件；数据负责「用哪个组件、怎么组合、传什么配置」，**不拆解组件内部结构**。
- **应用数据 ≠ 用户数据**：被数据驱动的是「应用数据」（应用的结构/组合/流程定义），
  与「用户数据」（保险库里的条目、密码）严格分离。
- **应用数据 = 随应用发布的声明式装配契约**（驱动组件/插件/事件路由），
  **永不运行时可变、永不含逻辑、安全决策留在引擎**。数据决定「长什么样」，
  引擎决定「什么能被允许」。

### 7.2 可数据化 vs 手写 vs 硬编码

| 类别 | 内容 | 决策 |
|------|------|------|
| 数据驱动 | 字段/列表/表单/详情（四类条目 login/note/secret/file 同构，收益最大） | 数据驱动 |
| 数据驱动 | 设置项、规则项 | 数据驱动 |
| 数据驱动 | 主题 tokens | 数据驱动（theme 插件，见 [design/spec.md](design/spec.md) §2） |
| 手写 React（原子组件） | 密码遮罩、Markdown 高亮、倒计时环形、附件进度 | 手写，注册进组件注册表，不拆开 |
| 硬编码确定性代码 | 解锁、恢复、审批默认拒绝、审计追加 | 硬编码，**永不数据化** |

### 7.3 红线（防 inner-platform effect）

- **应用数据一旦出现逻辑（条件/循环/计算），说明该写组件/服务，而不是加更多数据字段。**
- 安全流程（解锁/恢复/审批默认拒绝/审计追加）永远走确定性代码，任何「配置化」都是
  越界。

## 8. 与 Cordis 的关系（真 Cordis 用啥、自写啥）

### 8.1 用真 Cordis（D 层，`@cordisjs/core` 4.x）

| 能力 | 说明 |
|------|------|
| 插件 = Service | 函数带 `inject`+`apply(ctx)`，或 Service 子类 |
| ctx 服务容器 | `ctx.<key>` 查找服务 |
| `inject` 依赖声明 | 自动排加载顺序 |
| 类型化事件 | `emit` / `waterfall` / `parallel` / `serial` |
| 可逆副作用 | `ctx.effect()` / `ctx.on()`，卸载自动撤销 |
| 数据驱动装配 | `cordis.yml` + loader（`@cordisjs/plugin-loader`）；配置校验 `@cordisjs/schema` |
| 服务级替换/增强 | `ctx.isolate(name,label)` / `ctx.intercept(name,config)` / `ctx.provide/set/get` |

> 以上 API 名称为概念级引用，**具体签名以 `@cordisjs/core` 4.x 为准**，不写死不确定细节。

### 8.2 自写（Cordis 不管的部分）

1. **React 宿主薄层**：Cordis 是框架无关运行时，**不管 React/UI 布局**，没有
   「页面/组件/像素位置」概念。需要一个薄 React 宿主：
   - 读取 `cordis.yml` 装配结果（哪些插件、哪些槽位组件、顺序）；
   - 渲染三栏骨架（`topbar`/`sidebar`/`content`，写死）；
   - 把原子组件注册进组件注册表，把槽位组件按布局数据挂入；
   - 订阅 `theme.changed` 等事件触发重渲染。
2. **IPC 桥（ipc-bridge 插件）**：统一 IPC 门面 + mock/tauri 适配器；
   把 Rust 事件翻译成 TS Cordis 事件，把 TS 的审批结果/调用经 IPC 回传 Rust。
3. **Rust 侧模拟**：不移植 Cordis；用 trait 服务 + 事件总线模拟 Cordis 的
   Service/依赖注入/事件语义（见 §3/§5）。

## 9. 存储真相（现状澄清）

- **无数据库**，全是文件系统文件（与 [data-model.md](data-model.md) §2 一致）：

| 文件 | 内容 | 加密 |
|------|------|------|
| `{uuid}.item.lk` | 条目 | K_data |
| `index.lk` | 索引（条目+规则最小索引） | K_data |
| `{uuid}.tomb.lk` | 墓碑 | K_data |
| `{uuid}.attach.lk` + `{uuid}.{i}.chunk.lk` | 附件元数据 + 分块 | K_data / 每附件独立密钥 |
| `recovery.envelope` | 恢复信封 | K_recovery |
| `audit.log` | 审计（本地追加式，不上云） | HMAC（K_audit）防篡改 |
| `config.json` | 守护配置（同步 URL/轮询/空闲超时） | 明文（非敏感运行时配置） |

- 归属分界（与 §7.1 呼应）：
  - **敏感加密数据**（条目/索引/规则/附件/信封）→ Rust vault 落盘（文件）。
  - **非敏感运行时配置**（同步 URL/轮询间隔/空闲超时）→ `config.json` 明文，
    由 daemon（C 层）读写。
  - **UI 偏好（含主题）** → preference-store（D 层），localStorage/tauri store，
    **不进加密库、不进 config.json**。

## 10. 一致性核对与衔接

已通读 docs/ 下全部相关文档，结论如下：

| 文档 | 结论 |
|------|------|
| [architecture.md](architecture.md) | 不矛盾。已加 §3 插件化指针；`lk-core` 单一 crate 结论不变（内部重组为 A/B 边界） |
| [milestones.md](milestones.md) | 已重排：插入 M1.5 插件化改造；M0/M1 保持已完成；M2/M3 标签**不变**（授权门/桌面 = M2，浏览器填充 = M3），内容改为「在插件化骨架上实现」 |
| [decisions.md](decisions.md) | **待补映射**：本定案（选项 A/四层/事件总线/数据驱动边界/装配机制）尚未登记到决议集。按纪律应由后续会话补一行决议映射（本次不擅改决议集） |
| [design/spec.md](design/spec.md) | 已加衔接：§1 默认暗色「tokens 结构化以便扩展浅色」的落点 = theme 插件；§3 组件库的强交互组件 = 手写原子组件；§5 页面结构三栏 = 槽位骨架 |
| [data-model.md](data-model.md) | 不矛盾。A 层 vault-store 能力（条目/索引/墓碑/附件 CRUD、CAS、30 天延迟硬删）与该文档 §2/§4 一致 |
| [sync.md](sync.md) | 不矛盾。sync-engine 能力（变更发现、CAS 收敛、墓碑同步）与该文档一致；`item.changed` 推送对应 §3 上传 |
| [ipc.md](ipc.md) | 不矛盾。事件总线是 IPC 之上的解耦层，**不替代** JSON-RPC 2.0；ipc-bridge 是门面；session 插件对应 §3 令牌 |
| [authorization-gate.md](authorization-gate.md) | 不矛盾。authz-gate（B）承载三层模型/规则库/启动者判定；approval（D）= 弹窗 + 30s 倒计时；审批通道抽象对应 trait |
| [audit.md](audit.md) | 不矛盾。audit 插件能力（追加日志 + HMAC + 密钥轮换链）与该文档 §3/§3.1 一致 |
| [crypto.md](crypto.md) / [recovery.md](recovery.md) | 不矛盾。crypto/recovery 插件能力分别对应两文档的 KDF/AEAD/信封/重加密轮换 |
| [browser-fill.md](browser-fill.md) | 不矛盾。browser-fill 插件（D）对应 M3 协议，仍为「协议落定、实现 V1 之后」 |
| [cli.md](cli.md) | 不矛盾。daemon（C 层）对应 `lk daemon`；命令经 IPC 路由不变 |
| [testing.md](testing.md) | 无矛盾；**待补**：§4 里程碑出口映射尚未列出 M1.5（插件化改造出口 = 行为不回归测试），留待后续指针同步 |

### 10.1 里程碑编号决策（待船长确认）

- **推荐**：插件化改造作为**独立里程碑**插入 M1 之后、M2 之前（编号记作 **M1.5**），
  理由：① 它是「无行为回归的重组」，与 M2「新增授权门+桌面功能」性质不同，合并会
  混同「回归」与「新功能 bug」两种故障；② D 层宿主 + 槽位 + cordis.yml 装配是授权门
  与桌面端共同的地基，先立地基再盖楼。
- **编号保持 M2/M3 稳定**（不重排为 M3/M4），避免波及 authorization-gate.md /
  browser-fill.md / cli.md / testing.md / design/spec.md / README.md 中数十处
  M2/M3 引用。
- 此为**位置与编号建议**，标记「待船长确认」；若船长选择与 M2 合并或整体重排，
  本小节与 [milestones.md](milestones.md) 同步调整。
