# 本地 IPC 与守护进程规格（ipc）

- 状态：已拍板（D10）
- 关联：[crypto.md](crypto.md)（密钥仅内存）· [authorization-gate.md](authorization-gate.md)
  （最小字段响应）· [browser-fill.md](browser-fill.md)（M3 通道）

## 1. 角色模型

- **守护进程（daemon）**：`lk daemon`（CLI 子命令）或桌面应用内置实例。
  持解锁态；**密钥只存在于守护进程内存**（零落盘，锁定即擦除）。
- **客户端（client）**：`lk` 各子命令、桌面壳、浏览器扩展（M3，Native Messaging）
  ——统一经本地 IPC 访问守护进程，**任何客户端都不直接持钥**。
- 首次访问自动拉起守护进程；守护进程退出 = 锁定。

## 2. 传输与协议（D10）

- 传输：**Unix domain socket**（macOS/Linux）/ **Windows named pipe**。
  仅本用户可访问（权限 0600 / pipe ACL）。
- 协议：**JSON-RPC 2.0**（`id`/`method`/`params`/`result`/`error`），
  serde 序列化（`lk-core::ipc` 定义请求/响应类型）。
- 消息结构：`{ "jsonrpc": "2.0", "method": "...", "params": {...}, "id": n }`。
- 版本：每个方法带版本前缀，如 `vault.unlock`、`item.get`、`authz.evaluate`。
- 首启判定（M2.5）：桌面壳启动时查 `vault.status`——`initialized=false`（无库）
  → 初始化向导；`true`（有库）→ 解锁页；与 `unlocked` 正交（锁态即可响应）。

## 3. 会话令牌（D10）

- 解锁成功 → 守护进程签发**会话令牌**（高熵随机，如 256-bit），**随每次解锁轮换**。
- 后续所有请求必须携带令牌；令牌错误/过期 → `-32601` 风格错误（统一为
  `session.invalid`），客户端不得据此区分「库未解锁」与「令牌错」（防探测）。
- 令牌仅存在于客户端进程内存，不落盘。
- 锁定/超时/守护进程退出 → 令牌立即失效。

## 4. 方法与最小字段原则（D10）

| 方法 | 说明 | 返回（最小字段） |
|------|------|------------------|
| `vault.status` | 解锁态、**库是否已初始化**（M2.5 首启门控：无库 → 初始化向导）、同步水位、版本 | 布尔 ×2 + 水位戳 |
| `vault.init` | 建库：设主密码（**至少 8 位**，弱密码 → `vault.weak_password`）+ 生成恢复码/信封；已存在库 → `vault.exists` | 恢复码（仅展示一次） |
| `vault.unlock` | 主密码解锁 | 会话令牌 |
| `vault.lock` | 立即锁定 | 无 |
| `vault.recover` | 恢复：恢复码 + 新主密码（重置主密码，数据保留） | 新恢复码（仅展示一次） |
| `item.list` | 索引（解密态最小字段） | id/name/type/revision/deleted |
| `item.get` | 单条 | 完整解密条目 |
| `item.put` / `item.delete` | 写 | 新 revision |
| `item.export` | 导出 file 条目附件（整包下载） | 名称/MIME/大小 + base64 数据 |
| `sync.trigger` / `sync.poll` | 同步控制 | 变更摘要（不返回内容） |
| `authz.evaluate` | 授权门判定（M2） | 允许/拒绝 + 最小 env 集 |
| `approval.result` | 客户端回传审批结果（M2；`approval.request` 已移除，语义并入 `ApprovalChannel::open`） | accepted（是否接受） |
| `rule.add` / `rule.list` / `rule.remove` | 规则管理（M2，决策 #6） | 规则 / 规则列表 / 无 |
| `audit.list` | 审计查询 | 事件（无密钥值） |
| `audit.verify` | 校验审计 HMAC 链 | 已验证事件数 |
| `subscribe` | 推送通道订阅（M2；连接转入流模式，收 JSON-RPC notification 帧，决策 #3 A） | 无 |

- **最小字段原则**：IPC 响应只包含调用方被授权的最小已解密字段——例如
  `authz.evaluate` 只返回「被批准命令的 env 变量」，绝不返回整库内容
  （D10 原文：环境变量只注入被批准命令）。
- **错误码**：`vault.init` 的弱密码（`vault.weak_password`）与已存在库
  （`vault.exists`）错误码不同，但 UI 层统一文案不区分（防探测语义同
  §3 的 `session.invalid`）；`vault.recover` 的新主密码同策略。

## 5. 自动锁定（D10）

- **锁屏锁定**：检测到系统锁屏（macOS/Windows 会话锁事件）→ 立即锁定。
- **超时锁定**：空闲超时（默认 5 分钟，可配）→ 锁定。取值为**离散档位
  0 / 1 / 5 / 15 / 30 / 60 分钟**（0 = 下次请求即锁；补充拍板 #10，与设置页
  下拉一致，不接受自由数值）。
- 锁定动作：擦除内存密钥、失效令牌、停止同步轮询；客户端收到
  `session.invalid` 后回到解锁 UI。

## 6. 安全约束

- 守护进程 socket 路径/pipe 名含用户级随机组件，防跨用户劫持。
- 同一 socket 上不传主密码明文以外的敏感内容到非守护进程方（所有解密只发生在
  守护进程侧）。
- 限流：对 `vault.unlock` 失败计数 + 退避，防暴力（与 [recovery.md](recovery.md)
  的丢失策略一致，不引入额外泄露面）。
- M3 浏览器扩展经 **Chrome 官方 Native Messaging** 接入同一守护进程，不另开通道
  （见 [browser-fill.md](browser-fill.md)）。
