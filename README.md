# LightKey · 轻钥

个人密钥 / 私密信息管理工具。从零自研（把 Bitwarden 当“技术规格书”照抄设计，
不抄代码、不 fork、不以 Bitwarden/Vaultwarden 为底座），**客户端全开源（MIT）**。

> 当前状态：**M0 骨架 + V1 MVP 实施 spec 已完成**（2026-08-15 决议集）。
> 功能实现按 `docs/milestones.md` 里程碑推进。

## 设计要点（详见 docs/）

- **加密**：Argon2id(m=64MiB,t=3,p=4) 派生主密钥 → HKDF-SHA256 分叉
  数据加密 / 恢复信封 / 审计 HMAC 三密钥；AES-256-GCM（刻意不同于
  Bitwarden 的 CBC+HMAC）。
- **零知识彻底**：条目/索引全加密；BYO 存储（WebDAV/S3）只见密文文件
  与文件名时间戳。
- **同步**：加密索引 + 轮询（默认 60s，可配 15s~24h）；CAS + 墓碑，
  30 天延迟硬删；last-write-wins。
- **Agent 授权门**：默认拒绝 → 规则白名单 → 弹窗审批（30s 超时拒）；
  `lk inject -- <cmd>` 只给被批准命令注入 env。
- **恢复**：40 字符恢复码 + 恢复信封；三通道全丢 = 数据不可恢复（诚实文案）。

## 仓库结构

```
crates/lk-core/    核心库（加密/数据模型/同步/授权门/审计/IPC 类型）
crates/lk-cli/     CLI `lk`（含 daemon 宿主）
crates/lk-app/     Tauri 2 桌面壳
frontend/          React + TypeScript 前端（Vite）
docs/              实施规格集（docs/README.md 为索引；含前端设计规范与高保真原型）
```

## 构建与测试

```bash
# 核心 + CLI（任意平台，Linux 上 Tauri 壳需要 webkit2gtk，由 CI 在 Win/mac 检查）
cargo test                      # 默认成员 = lk-core + lk-cli
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings

# 前端
cd frontend && npm install && npm run build
```

验收平台：Windows + macOS；Linux 冒烟不阻塞。CI 见 `.github/workflows/ci.yml`。

## 文档索引

[`docs/README.md`](docs/README.md) 是文档地图；[`docs/decisions.md`](docs/decisions.md)
是 2026-08-15 拍板的决议记录（规格的唯一权威来源）。

## 许可

MIT（客户端代码）。服务端（如未来有）不开源；付费能力暂缓。
