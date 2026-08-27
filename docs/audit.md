# 审计日志规格（audit）

- 状态：已拍板（D11）＋补充拍板 #11；审计锚点（issue #75）为 M2.75 后增强
- 关联：[crypto.md](crypto.md)（K_audit）· [ipc.md](ipc.md)（守护进程写审计）
  · [authorization-gate.md](authorization-gate.md)（事件来源之一）· [cli.md](cli.md)（`lk audit --verify`）

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
  "channel": "cli | desktop | approval | wsl-bridge",   // 来源通道（wsl-bridge = WSL 内客户端经 interop stdio 桥，补充拍板 #14，见 [cross-subsystem.md](cross-subsystem.md) §7.5）
  "hmac": "<base64, HMAC-SHA256(K_audit, 事件规范化字节)>"
}
```

### 摘要原则

- `command` 记录**命令摘要**而非完整 argv：例如 `npm publish <redacted>`，
  `env -i lk inject -- <sha256:前8位>`。完整 argv 中可能含密钥/令牌，一律脱敏。
- 敏感参数（如可能为 secret 的长参数）替换为 `<redacted>`；规则见
  [authorization-gate.md](authorization-gate.md) 的脱敏约定。

### 启动者判定与来源通道

- `starter` 取自 [authorization-gate.md](authorization-gate.md) 的
  **进程链回溯**结果（顶层可归属进程），`target` 为最终被调用命令。
- **常规命令（`item.*` / `vault.*` / `rule.*` 等）同样记录真实调用方**
  （#66）：守护进程在分发层按 IPC 对端派生一次，随命令写入审计——
  - socket 客户端（CLI / WSL bridge）：starter = 对端进程链回溯结果
    （bridge 对端回溯出 interop 链顶层，可与本地 CLI 区分）；
  - 桌面内嵌直调（桌面壳 command 桥，无 IPC 对端）：`starter=desktop`、
    `channel=desktop`；
  - 守护进程自身触发（空闲自动锁定等）：`starter=daemon`
    （channel 沿用 `cli` 枚举——该字段建模客户端通道，无独立 daemon 值）；
  - 回溯失败如实记 `unknown`（与授权门 fail-closed 同一判定路径）。
- `channel` 缺省 `cli`；`rule.*` / `authz.evaluate` 支持客户端参数标注
  （`desktop` / `wsl-bridge`，仅审计来源标注），未标注时按对端来源。

## 3. 防篡改（D11）

- 每条事件附带 `hmac`：`HMAC-SHA256(K_audit, canonical(event))`；
  `canonical` 为事件字段的确定性序列化（字段排序固定）。
  `K_audit` 指轮换后对应的当前密钥（轮换链见 §3.1）。
- **`hmac` 不进前端**（补充拍板 #11）：防篡改校验是守护进程/CLI 侧职责
  （`audit.list` IPC 响应与桌面 UI 审计事件流均为只读展示、不含 `hmac`，
  前端 `AuditEvent` 类型不建模该字段）；篡改检测由守护进程校验链完成。
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

### 3.2 文件外锚点（截断可证明，issue #75）

- **问题**：审计日志只是本地 0600 追加式文件，没有任何**文件外可信锚点**。
  同用户攻击者可截尾抹掉近期事件、或删掉整文件让守护进程重建空链，截断后的
  链仍能通过「第一条到最后一条」的 HMAC 校验。设计取向：同用户总能写数据目录，
  目标是**截断可证明**（truncation is provable），不是截断可预防。
- **锚点值**：`{ ordinal, last_hmac }`——`ordinal` = 锚点建立时链的事件总数；
  `last_hmac` = 最后一条事件的 `hmac`（均从日志文件直接读出，**无需 K_audit**，
  因此锁定态/解锁态都能写锚点）。
- **写入点**：在**解锁 / 锁定 / 恢复（密钥轮换）/ 守护进程干净关闭**时同步写入
  （低频点），并由后台线程每 60s **异步 flush** 一次——不在热路径（同步触发 /
  密钥轮换 / 审批）上同步阻塞；断开顺序无关紧要，idempotent 覆盖。
- **平台存储**：优先写入平台安全存储——Windows Credential Manager / macOS
  Keychain / Linux secret-service·keyutils（经 `keyring` 抽象）。**降级原则**：
  平台不可用 → **fail-open** 降级到数据目录 0600 侧写文件 `audit.anchor`
  （`FileAnchorSidecar`，原子写），并给出明确「锚点不可用、防篡改能力减弱」
  警告——**绝不阻断 vault 解锁**。侧写更弱（同用户可改写文件本身），但能证明
  「链被整体重写/截尾」，比没有强（文档标注为最弱档）。
- **校验语义**（`AuditLog::verify` HMAC 链 + `check_anchor` 交叉核对额外执行）：
  - 链 `ordinal <` 锚点 `ordinal` → **截断**（tail 被抹），definite；
  - 链与锚点 ordinal 相等但 `last_hmac` 不同 → **锚定事件被换/伪造**；
  - 锚点缺失（平台与侧写都没有）→ 无法证明完整，同样计为截断；
  - 链 `ordinal >` 锚点 `ordinal` → 锚点落后于链尾（锚点后追加的事件），**不是
    截断**，HMAC 链自身已校验，只在结果里提示「锚点未覆盖尾部 N 条」。
- **`lk audit --verify`**（经 `audit.verify` RPC / `audit_verify()`）交叉核对锚点：
  HMAC 链校验通过后，若有截断/锚点缺失/锚定事件被篡改 → 明确报
  「截断检测（truncation detected）」，**退出非零**（[cli.md](cli.md)）。
- **`vault.status`**：暴露可选字段 `auditAnchorOk: bool`（`#[serde(default)]`；
  前端类型 `auditAnchorOk?: boolean`）。守护进程启动/解锁时做「锚点 vs 链自检」，
  锚点可用且链未被截断 = `true`；降级到侧写（平台不可用）或检测到截断/锚点缺失 =
  `false`。桌面 UI 可据此给用户「审计链可能被截断/防篡改能力减弱」警告；旧守护
  进程不返回该字段时前端按未知处理（不误报）。

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
