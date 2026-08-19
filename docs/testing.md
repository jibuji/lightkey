# 测试策略与 CI（testing）

- 状态：已拍板（D13/D2）
- 关联：[milestones.md](milestones.md)（出口标准）· `.github/workflows/ci.yml`（骨架）

## 1. 测试三层（D13）

### 第一层：Rust 核心单元 + 属性测试（`lk-core`）

- 单元：各模块行为（KDF 参数、密文往返、条目 CRUD 不变量、审计追加语义）。
- 属性测试（proptest）：
  - **加密往返**：任意明文 → 加密 → 解密 == 明文；任意字节翻转 → 解密失败。
  - **CAS 冲突**：base revision 过期 → 写失败；last-write-wins 收敛正确。
  - **墓碑收敛**：任意多端、任意同步顺序 → 最终一致（见 [sync.md](sync.md) §4）。
  - **恢复信封**：恢复码往返一致；错误恢复码失败；重置后旧钥不可解新数据。
- 平台差异分支（进程链回溯、named pipe vs UDS）用 cfg 隔离 + Windows CI 覆盖，Linux 冒烟由本地承担。

### 第二层：E2E 双客户端冲突合并

- 两个独立客户端（两个守护进程实例）指向同一 BYO 存储（本地模拟 WebDAV/S3）。
- 场景：离线双改同条目 → 上线同步 → CAS 冲突 → last-write-wins 收敛；
  一端删除 → 墓碑传播 → 对端收敛；附件分块断点续传。
- 端到端脚本驱动 `lk` CLI（[cli.md](cli.md)），断言存储端只见密文。

### 第三层：安全专项

- **授权门绕过尝试**（[authorization-gate.md](authorization-gate.md) §7 清单）：
  伪造 cwd / 符号链接目录 / 跨会话进程 / 直连 IPC 调 `authz.evaluate` /
  手动改加密规则文件 → 全部 fail-closed 且审计留痕。
- **审计篡改检测**：改任意字节 → HMAC 校验失败；追加式不可就地修改
  （[audit.md](audit.md) §6）。
- **IPC 边界**：无令牌请求、错令牌、锁定时请求 → 统一错误，不泄露状态。

## 2. 测试数据纪律（D13）

- **测试 fixture 密钥不进仓库**：所有测试密钥/密码/恢复码在测试内生成
  （随机），或从环境变量注入；仓库内不出现任何真实或半真实密钥。
- 涉及「含密钥」的样例文档（如示例密文）用明显占位符，且不入 CI 断言。

## 3. CI（GitHub Actions，骨架已建）

`.github/workflows/ci.yml`（船长裁定收敛为 Windows 优先，替代原 D2 CI 部分）：

| Job | 平台 | 内容 |
|-----|------|------|
| desktop-windows | windows-latest | fmt / clippy(-D warnings) / test（`lk-core` `lk-cli`）/ `cargo check --workspace`（含 Tauri 壳与 Windows 资源生成） |
| frontend | ubuntu-latest | `npm ci` + `npm run build`（tsc + vite） |

- **Windows 是主开发测试平台**（船长本机 Windows WSL）；macOS/Linux 桌面构建
  不再占 CI 矩阵（Linux 冒烟由本地承担）。
- 工具链固定：`rust-toolchain.toml`（1.94）+ `dtolnay/rust-toolchain@stable` 对齐，
  `Swatinem/rust-cache` 缓存。
- 属性测试在 CI 跑固定种子（回归可复现）+ 每日/PR 随机种子抽查（可选后续）。

## 4. 里程碑出口映射

| 里程碑 | 必过测试 |
|--------|----------|
| M0 | 第一层（加密往返/CAS/墓碑/信封）+ 单机 E2E 脚本 |
| M1 | 第二层双客户端冲突合并全部场景 |
| M1.5 | 行为不回归：M0/M1 全量测试（第一层 + E2E e2e_m0.sh / e2e_m1.sh）重组后全绿；密文格式/存储布局/IPC 协议零变更；D 层事件总线单测（item.changed 三方响应、session.unlocked/locked、theme.changed 重渲染、clipboard.copied Toast+30s 清除） |
| M2 | 第三层安全专项 + 授权门单测 + 桌面验收（Windows） |
| M2.5 | 首启门控：`vault.status.initialized` 单测（无库/有库）+ 初始化向导四步流单测（弱/强/不一致门控、恢复码勾选门控、完成跳转解锁、统一错误文案）+ 有库启动 → 解锁页回归（host/浏览器 E2E） |
| M3 | 填充协议集成（扩展 ↔ 守护进程）模拟 |
