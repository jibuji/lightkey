# 总体架构（V1 MVP）

- 状态：已拍板（D1/D2/D15）
- 关联：[milestones.md](milestones.md)（范围）· [decisions.md](decisions.md)（决议）

## 1. 定位与交付范围

V1 MVP 交付三样东西：

1. **核心库 `lk-core`**（Rust crate）：加密、数据模型、同步、授权门、审计、IPC 协议类型。
2. **CLI `lk`**（Rust crate）：复用 `lk-core`；含 `lk daemon` 守护进程宿主。
3. **桌面应用**（Tauri 2 壳 `lk-app` + React 前端）：复用 `lk-core`。

浏览器扩展是 **M3 里程碑**（V1 之后），本阶段只落协议规格（[browser-fill.md](browser-fill.md)）。

## 2. 技术栈（D2）

| 层 | 选型 | 说明 |
|----|------|------|
| 语言 | Rust（1.94，workspace 固定，见 `rust-toolchain.toml`） | 核心 + CLI + 桌面壳 |
| 桌面壳 | Tauri 2 | 系统 WebView + 原生壳 |
| 前端 | React + TypeScript + Vite | 位于 `frontend/` |
| 验收平台 | **Windows + macOS** | Linux 冒烟不阻塞（CI 见 [testing.md](testing.md)） |

## 3. 组件与边界

```
┌────────────────────────────────────────────────────────────┐
│ 桌面应用 lk-app (Tauri 2)            CLI lk                 │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │ React 前端  │   │ 壳逻辑       │   │ 子命令 / 服务      │   │
│  │ (frontend/)│──▶│ 窗口·托盘·审批 │   │ daemon 宿主       │   │
│  └────────────┘   │ 弹窗·IPC 桥   │   └────────┬─────────┘   │
│                   └──────┬───────┘            │             │
└──────────────────────────┼────────────────────┼─────────────┘
                           │  本地 IPC（JSON-RPC 2.0）
                           ▼                    ▼
                  ┌────────────────────────────────────┐
                  │  lk-core（唯一实现库，双端复用）       │
                  │  crypto · model · sync · authz ·    │
                  │  audit · ipc(协议类型)               │
                  └────────────────────────────────────┘
```

**边界纪律**：

- `lk-core` 是**唯一**包含业务逻辑的库；CLI 与桌面壳只做编排与呈现，不复制逻辑。
- 密钥等敏感内存仅在守护进程内存中（[ipc.md](ipc.md)）；任何进程内不落盘明文。
- 前端不直接接触加密层——一切经桌面壳 → 本地 IPC → 守护进程 → `lk-core`。
- 未来服务端（若做）不在此仓库/不开源；CLI 与桌面不依赖任何服务端能力。

## 4. Workspace 布局

```
lightkey/
├── Cargo.toml                 # workspace：members + default-members（core+cli）
├── rust-toolchain.toml        # 固定 1.94，本地与 CI 同版本
├── crates/
│   ├── lk-core/               # 核心库（占位模块已声明，M0 起实现）
│   ├── lk-cli/                # `lk` 二进制（命令树已声明）
│   └── lk-app/                # Tauri 2 壳（窗口、tauri.conf.json、capabilities、图标占位）
├── frontend/                  # React + TS（Vite；dev 端口 1420 与 tauri devUrl 一致）
├── docs/                      # 本规格集（docs/README.md 为索引）
└── .github/workflows/ci.yml   # CI 骨架（测试策略见 docs/testing.md）
```

**default-members 说明**：workspace 默认成员为 `lk-core` + `lk-cli`，因此在任何平台
`cargo test`/`cargo check`/`cargo clippy` 默认只构建这两个 crate（Linux 上 Tauri 需
webkit2gtk 系统库，不阻塞）；`lk-app` 由 CI 在 Windows/macOS 上以 `--workspace`
显式检查。

## 5. 关键横切设计（速览，细节见各规格）

| 主题 | 一句话 |
|------|--------|
| 加密 | Argon2id(64MiB,3,4) → 主密钥；HKDF-SHA256 分叉 + AES-256-GCM；自描述密文（[crypto.md](crypto.md)） |
| 数据 | 条目级密文 blob + 加密索引；CAS + last-write-wins；30 天墓碑（[data-model.md](data-model.md)） |
| 同步 | BYO 存储（WebDAV/S3）无服务器；加密索引 + 轮询（默认 60s）；无推送（[sync.md](sync.md)） |
| 守护进程 | 持解锁态，密钥仅内存；会话令牌随解锁轮换（[ipc.md](ipc.md)） |
| 授权门 | 默认拒绝 → 规则白名单 → 弹窗审批（30s 超时拒）（[authorization-gate.md](authorization-gate.md)） |
| 审计 | 追加式 + HMAC 防篡改；默认永久保留（[audit.md](audit.md)） |
| 恢复 | 40 字符恢复码 + 恢复信封（Argon2id 派生信封密钥）（[recovery.md](recovery.md)） |

## 6. 非目标（V1 明确不做，D15）

- 服务端/云同步托管（BYO 存储是 V1 形态）。
- 付费能力与付费墙；官方签名构建、远程审批中继等付费边界推迟到验证后再议。
- 浏览器扩展实现（仅协议规格，M3）。
- 条目数限制（免费版永不设限）。
- 多用户/共享库、团队功能。
