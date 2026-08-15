# 审计日志规格（audit）

- 状态：已拍板（D11）
- 关联：[crypto.md](crypto.md)（K_audit）· [ipc.md](ipc.md)（守护进程写审计）
  · [authorization-gate.md](authorization-gate.md)（事件来源之一）

## 1. 定位

- 审计是**本地、追加式**日志：只允许追加，不允许就地修改/删除（防篡改与
  取证需求）。
- 记录的是「**密钥/敏感操作被谁、何时、如何请求**」的元数据；**密钥值
  永不明文**（D11）。
- 默认**永久保留**；后续版本允许用户设置滚动保留时间（M2 桌面「设置」页
  提供入口，见 [design/spec.md](design/spec.md)）。

## 2. 事件模型（D11 字段集）

```jsonc
{
  "eventId": "<uuid>",
  "ts": "<ISO-8601 UTC>",            // 时间戳
  "starter": "<启动者进程>",          // 例如 /usr/bin/zsh、进程链顶层（见下）
  "target": "<目标程序>",             // 例如 npm、node、python3
  "command": "<命令摘要>",            // 命令摘要——见「摘要原则」
  "result": "allowed | denied | timeout",
  "channel": "cli | desktop | approval",   // 来源通道
  "hmac": "<base64, HMAC-SHA256(K_audit, 事件规范化字节)>"
}
```

### 摘要原则

- `command` 记录**命令摘要**而非完整 argv：例如 `npm publish <redacted>`，
  `env -i lk inject -- <sha256:前8位>`。完整 argv 中可能含密钥/令牌，一律脱敏。
- 敏感参数（如可能为 secret 的长参数）替换为 `<redacted>`；规则见
  [authorization-gate.md](authorization-gate.md) 的脱敏约定。

### 启动者判定

- `starter` 取自 [authorization-gate.md](authorization-gate.md) 的
  **进程链回溯**结果（顶层可归属进程），`target` 为最终被调用命令。

## 3. 防篡改（D11）

- 每条事件附带 `hmac`：`HMAC-SHA256(K_audit, canonical(event))`；
  `canonical` 为事件字段的确定性序列化（字段排序固定）。
  `K_audit` 指轮换后对应的当前密钥（轮换链见 §3.1）。
- 密钥值永不明文——即使审计文件被读走，也无法伪造/篡改事件而不被发现。
- 追加式实现：文件以 append-only 模式打开；事件落盘成功后才返回给调用方；
  写失败（磁盘满/权限）→ 上报错误，不静默丢失。

### 3.1 审计密钥轮换（验证链）

- 触发场景：主密码重置恢复流程会更换 K_audit（[recovery.md](recovery.md) §3 第 3 步）；
  未来如提供显式轮换能力，同样适用本协议。
- 协议：切换前，先用**旧 K_audit** 追加签名一条「审计密钥轮换」事件——在通用
  事件字段上扩展 `oldKeyId` / `newKeyId`（密钥标识/指纹，不含密钥材料），`ts`
  记录切换时间。
- 验证链语义：**新密钥验证轮换点之后的新事件**；**旧事件通过链条追溯到
  轮换事件**（轮换事件本身由旧密钥签名）——旧日志全程可验证，永久保留与
  防篡改语义不变。

## 4. 写入方与查询

- 写入：**守护进程**（[ipc.md](ipc.md)）是唯一写入方——所有敏感操作都经守护
  进程执行或裁决，审计在其边界记录，客户端不可绕过。
- 查询：`lk audit`（CLI，见 [cli.md](cli.md)）与桌面「审计」页（M2）只读。
- 审计文件位置：用户数据目录，权限 0600；不作为同步内容进 BYO 云
  （本地事实，不上云）。

## 5. 保留与滚动（默认永久，后续可配）

- V1 默认永久保留。
- 预留配置项 `audit.retention`（滚动保留窗口）；实现时不阻止追加、
  按窗口清理最旧事件段；滚动清理也记录一条审计事件（自我审计）。

## 6. 测试要点（见 [testing.md](testing.md)）

- 篡改检测：改任意字节 → HMAC 校验失败。
- 追加式：验证不可就地修改（open 模式 + 写入路径权限）。
- 绕过尝试：直接改审计文件、直接调用受保护 IPC 方法不经授权门 → 必须留痕。
