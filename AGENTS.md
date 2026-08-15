# AGENTS.md — LightKey 项目知识

面向几乎每个未来会话的项目级知识；细节一律指向权威文件，不在此复制。

## 项目一句话

轻钥 LightKey：个人密钥/私密信息管理工具，从零自研（不 fork Bitwarden），
客户端全开源（MIT）。当前为 **M1（同步）完成 + M2 授权门/桌面** 阶段。

## 规格是唯一权威

- 所有设计决策见 [`docs/decisions.md`](docs/decisions.md)（2026-08-15 拍板，
  勿自行变更；发现矛盾走 needs-decision 上报）。
- 文档地图：[`docs/README.md`](docs/README.md)；里程碑：[`docs/milestones.md`](docs/milestones.md)。
- 文档语言为中文；标识符/命令/协议字段用英文。

## 常用命令

- 核心+CLI 测试/检查（Linux 上 Tauri 壳需 webkit2gtk，CI 在 Windows 检查；
  Windows 优先，补充拍板 #4）：
  `cargo test` / `cargo fmt --all -- --check` / `cargo clippy --all-targets -- -D warnings`
- 同步 E2E（M1 双客户端）：`bash scripts/e2e_m1.sh [lk-binary-path]`；
  单机回归：`bash scripts/e2e_m0.sh`（都用 `file://` 本地模拟存储，无需凭据）。
- 前端：`cd frontend && npm install && npm run build`（Vite 端口 1420 与
  `crates/lk-app/tauri.conf.json` 的 devUrl 一致）。
- CI 骨架：`.github/workflows/ci.yml`。

## 交付纪律

- 本仓库为 no-mistakes 交付：改动经 `/no-mistakes` 管道验证后开 PR，
  不直接推默认分支。
- 测试 fixture 密钥不进仓库（testing.md）。
- 前端设计评审用 agent_browser 对
  `docs/design/prototype/`（零构建原型）截图；评审流程见
  `docs/design/spec.md` §7。

## 里程碑状态

- [x] M0 骨架 + spec：workspace、CI、LICENSE、docs/、设计规范 + 原型
- [x] M0 功能实现（核心库 + CLI 单机闭环）
- [x] M1 同步（BYO 变更发现 + CAS + 墓碑；`lk sync` / `lk config`；存储后端
  trait + 本地模拟/WebDAV/S3 实现；E2E `scripts/e2e_m1.sh`）
- [x] M1 并发结构（G1 根治）：同步轮次 = 抓取无锁 + 应用短锁两阶段；命令与
  后台同步并发，网络 I/O 不持守护进程锁；vault 内存用读写锁（权限层与数据层
  互斥解耦，见 `crates/lk-cli/src/daemon.rs` 模块文档）
- [ ] M2 授权门 + 桌面 · [ ] M3 浏览器填充

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
