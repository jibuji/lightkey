# 总体架构（V1 MVP）

- 状态：已拍板（D1/D2/D15）；插件化边界见 [plugin-architecture.md](plugin-architecture.md)
- 关联：[milestones.md](milestones.md)（范围）· [decisions.md](decisions.md)（决议）
  · [plugin-architecture.md](plugin-architecture.md)（M1.5 插件化落地层）

## 1. 定位与交付范围

V1 MVP 交付三样东西：

1. **核心库 `lk-core`**（Rust crate）：加密、数据模型、同步、授权门、审计、IPC 协议类型。
2. **CLI `lk`**（Rust crate）：复用 `lk-core` + `lk-daemon`；`lk daemon` 入口（`lk_daemon::run(dir)`）。
3. **桌面应用**（Tauri 2 壳 `lk-app` + React 前端）：复用 `lk-core`。

**产物矩阵补充（跨子系统桥，补充拍板 #14，M2.75）**：同一 workspace 无代码
分叉，新增 Linux 产物 `lk`（`x86_64-unknown-linux-gnu`，release 双产物之一）——
供 Linux 环境（原生 Linux 与 WSL2）调用，**按运行环境自动选连通目标**：原生
Linux → 本地 UDS 守护实例（Linux 侧 GUI 的宿主），WSL2 → 经 `lk.exe bridge`
连 Windows 主机 GUI。Windows 侧 `lk.exe` 兼任 bridge stdio 中继（随桌面安装
包落地到安装目录），且无论被谁调用（Windows 终端或 WSL interop）都连 Windows
主机 GUI。判定矩阵详见 [cross-subsystem.md](cross-subsystem.md) §7.0。

浏览器扩展是 **M3 里程碑**（V1 之后），本阶段只落协议规格（[browser-fill.md](browser-fill.md)）。

## 2. 技术栈（D2）

| 层 | 选型 | 说明 |
|----|------|------|
| 语言 | Rust（1.94，workspace 固定，见 `rust-toolchain.toml`） | 核心 + CLI + 桌面壳 |
| 桌面壳 | Tauri 2 | 系统 WebView + 原生壳 |
| 前端 | React + TypeScript + Vite | 位于 `frontend/` |
| 验收平台 | **Windows（主开发测试平台，船长裁定）**；前端构建在 ubuntu；macOS/Linux 桌面构建不再占 CI 矩阵（CI 见 [testing.md](testing.md)） |

## 3. 组件与边界

```
┌────────────────────────────────────────────────────────────┐
│ 桌面应用 lk-app (Tauri 2)            CLI lk                 │
│  ┌────────────┐   ┌──────────────┐   ┌──────────────────┐   │
│  │ React 前端  │   │ 壳逻辑       │   │ 子命令 / 服务      │   │
│  │ (frontend/)│──▶│ 窗口·托盘·审批 │   │ daemon 入口       │   │
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

**插件化落地（M1.5 起，见 [plugin-architecture.md](plugin-architecture.md)）**：

- `lk-core` 保持**单一 crate**，内部按插件边界重组为 **A 层数据平面**（crypto/
vault-store/recovery/audit/session）与 **B 层能力域**（storage-backend/sync-engine/
authz-gate），trait 服务 + 事件总线**模拟** Cordis 语义（不移植 Cordis）。
- **C 层宿主 daemon**（共享 crate `crates/lk-daemon`）：装配 A/B、IPC 路由、空闲自动锁定、config.json。
- **D 层桌面/前端**用**真 Cordis**（`@cordisjs/core` 4.x）+ 薄 React 宿主；插件清单与
  inject 依赖图见 plugin-architecture.md §3/§4。
- 安全核心（加密/数据/同步/审计）留在 Rust，不重写为 TS；CLI 与 Tauri 壳只做
  编排与呈现（与本节纪律一致，插件化不放松此边界）。

## 4. Workspace 布局

```
lightkey/
├── Cargo.toml                 # workspace：members + default-members（core+daemon+cli）
├── rust-toolchain.toml        # 固定 1.94，本地与 CI 同版本
├── crates/
│   ├── lk-core/               # 核心库（占位模块已声明，M0 起实现）
│   ├── lk-daemon/             # C 层守护进程宿主（决策 #2 A：下沉共享，CLI 与桌面复用）
│   ├── lk-cli/                # `lk` 二进制（命令树已声明）
│   └── lk-app/                # Tauri 2 壳（窗口、tauri.conf.json、capabilities、图标占位）
├── frontend/                  # React + TS（Vite；dev 端口 1420 与 tauri devUrl 一致）
├── docs/                      # 本规格集（docs/README.md 为索引）
└── .github/workflows/release.yml  # 发布流水线（release-only 质量门禁，见 docs/testing.md §3）
```

**default-members 说明**：workspace 默认成员为 `lk-core` + `lk-daemon` + `lk-cli`，因此在任何平台
`cargo test`/`cargo check`/`cargo clippy` 默认只构建这三个 crate（Linux 上 Tauri 需
webkit2gtk 系统库，不阻塞）；`lk-app` 在 Windows 上检查/构建（本地 `cargo check
--workspace` 交叉目标，或 release 流水线的 `cargo tauri build`；船长裁定收敛为
Windows 优先，见 [decisions.md](decisions.md) 补充拍板 #4）。

## 5. 关键横切设计（速览，细节见各规格）

| 主题 | 一句话 |
|------|--------|
| 加密 | Argon2id(64MiB,3,4) → 主密钥；HKDF-SHA256 分叉 + AES-256-GCM；自描述密文（[crypto.md](crypto.md)） |
| 数据 | 条目级密文 blob + 加密索引；CAS + last-write-wins；30 天墓碑（[data-model.md](data-model.md)） |
| 同步 | BYO 存储（WebDAV/S3）无服务器；加密索引 + 轮询（默认 60s）；无推送（[sync.md](sync.md)） |
| 守护进程 | 持解锁态，密钥仅内存；会话令牌随解锁轮换（[ipc.md](ipc.md)） |
| 跨子系统桥 | WSL Linux `lk` → interop stdio → `lk.exe bridge` → named pipe；无新增监听面，协议零变更（[cross-subsystem.md](cross-subsystem.md)） |
| 授权门 | 默认拒绝 → 规则白名单 → 弹窗审批（30s 超时拒）（[authorization-gate.md](authorization-gate.md)） |
| 审计 | 追加式 + HMAC 防篡改；默认永久保留（[audit.md](audit.md)） |
| 恢复 | 40 字符恢复码 + 恢复信封（Argon2id 派生信封密钥）（[recovery.md](recovery.md)） |

## 6. 非目标（V1 明确不做，D15）

- 服务端/云同步托管（BYO 存储是 V1 形态）。
- 付费能力与付费墙；官方签名构建、远程审批中继等付费边界推迟到验证后再议。
- 浏览器扩展实现（仅协议规格，M3）。
- 条目数限制（免费版永不设限）。
- 多用户/共享库、团队功能。
