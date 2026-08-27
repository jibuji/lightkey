# 测试策略与 CI（testing）

- 状态：已拍板（D13/D2）
- 关联：[milestones.md](milestones.md)（出口标准）· `.github/workflows/release.yml`（发布前置门禁，2026-08-27 裁定）

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
- **跨子系统桥安全专项**（补充拍板 #14，[authorization-gate.md](authorization-gate.md)
  §7 增补清单）：伪造 `\\wsl.localhost` cwd 变体归一化后一致匹配不绕过 /
  interop 禁用显式失败 / 版本不匹配拒绝服务 / 会话令牌随解锁轮换、进程内存
  独占 → 全部 fail-closed 且审计留痕（`channel=wsl-bridge`）。

### 第四层补充：跨子系统 E2E（M2.75，补充拍板 #14）

- `scripts/e2e_cross_subsystem.sh`：宿主需 WSL2 + 桌面包，CI 无 WSL 时跳过。
  流程：WSL 内 Linux `lk` unlock → item list → `authz.evaluate` 弹窗批准 →
  Linux 子进程收到注入 env；断言审计含 `wsl-bridge` 事件、探测失败分型与
  目标可见性（stderr 提示 + `lk status` 目标字段）。规格见
  [cross-subsystem.md](cross-subsystem.md) §10；**要执行测试**（下载哪些 Release
  产物、安装、跑测）→ [testing-cross-subsystem.md](testing-cross-subsystem.md)。

## 2. 测试数据纪律（D13）

- **测试 fixture 密钥不进仓库**：所有测试密钥/密码/恢复码在测试内生成
  （随机），或从环境变量注入；仓库内不出现任何真实或半真实密钥。
- 涉及「含密钥」的样例文档（如示例密文）用明显占位符，且不入 CI 断言。
- 该红线不受跨子系统桥（M2.75）新增测试影响：`e2e_cross_subsystem.sh`
  同样只在测试内生成密钥或从环境变量注入，仓库不出现任何真实密钥。

## 3. CI（GitHub Actions，release-only）

**2026-08-27 船长裁定：CI 只在 release 时运行。** 原 `.github/workflows/ci.yml`
（main push / 全部 pull_request 触发）已删除，全部质量检查收敛为
`.github/workflows/release.yml` 的**构建前置门禁**——发布前必须绿：

| Job | 平台 | 门禁内容（打包前） |
|-----|------|--------------------|
| check-version | ubuntu-latest | 发布 tag（去 v 前缀）== lk-cli package version（#34） |
| build-windows | windows-latest | `cargo fmt --all -- --check` · clippy `-D warnings`（三 crate）· `cargo test`（三 crate）· 前端 `npm ci` + `npm test` + `npm run build` |
| build-linux-cli | ubuntu-latest | clippy `-D warnings`（lk-cli）· `cargo test`（lk-cli） |

- 触发面：tag `v*` push / `workflow_dispatch`（不带 release_tag 只留
  Actions artifact；带则补发到既有 Release，不移动标签）。
- **每日开发提交不在 GitHub 侧跑任何 workflow**——本地承担：Windows 全量
  （fmt/clippy/test 三 crate + 前端）+ WSL/Linux 侧同口径（覆盖 unix 分支），
  见 AGENTS.md「常用命令」。
- Windows 仍是主开发测试平台（船长本机 Windows WSL）；macOS/Linux 桌面构建
  不占发布矩阵（Linux 冒烟由本地承担）。
- 工具链固定：`rust-toolchain.toml`（1.94）+ `dtolnay/rust-toolchain@stable`
  对齐，`Swatinem/rust-cache` 缓存。
- 属性测试在 CI 跑固定种子（回归可复现）+ 随机种子抽查（可选后续）。

## 4. 里程碑出口映射

| 里程碑 | 必过测试 |
|--------|----------|
| M0 | 第一层（加密往返/CAS/墓碑/信封）+ 单机 E2E 脚本 |
| M1 | 第二层双客户端冲突合并全部场景 |
| M1.5 | 行为不回归：M0/M1 全量测试（第一层 + E2E e2e_m0.sh / e2e_m1.sh）重组后全绿；密文格式/存储布局/IPC 协议零变更；D 层事件总线单测（item.changed 三方响应、session.unlocked/locked、theme.changed 重渲染、clipboard.copied Toast+30s 清除） |
| M2 | 第三层安全专项 + 授权门单测 + 桌面验收（Windows） |
| M2.5 | 首启门控：`vault.status.initialized` 单测（无库/有库）+ 初始化向导四步流单测（弱/强/不一致门控、恢复码勾选门控、完成跳转解锁、统一错误文案）+ 有库启动 → 解锁页回归（host/浏览器 E2E） |
| M2.75 | 跨子系统桥：`path_ns` 归一化 / bridge 帧透传字节保真 / 版本校验三态单测 + 授权门绕过清单增补四项 + `e2e_cross_subsystem.sh`（宿主无 WSL 时跳过） |
| M3 | 填充协议集成（扩展 ↔ 守护进程）模拟 |
