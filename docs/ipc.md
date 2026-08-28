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

### 2.1 跨子系统 stdio 桥（补充拍板 #14，M2.75）

- **CLI 按运行环境选连通目标**（判定矩阵见
  [cross-subsystem.md](cross-subsystem.md) §7.0）：Linux `lk` 在 WSL → 连
  Windows 主机 GUI；原生 Linux → 本地 UDS；`lk.exe` 恒走 named pipe 连
  Windows 主机 GUI（无论 Windows 原生还是被 WSL interop 调用）。
- 场景：WSL2 内 Linux 原生 `lk` 连接同机 Windows 桌面守护实例。WSL/Windows
  边界上 UDS 与 named pipe 互不可达，故增加一条 stdio 中继通道：
  Linux `lk` 把行 JSON JSON-RPC 帧经 WSL interop 管道交给 `lk.exe bridge`
  （Windows PE，随桌面包安装），后者原样中继到 named pipe 并回写响应。
- 协议零变更：帧格式、会话令牌、审批编排全部照旧；bridge 不做任何业务
  解析（除版本校验外原样透传），决策权始终在守护进程；一进程一请求，
  首连校验版本主.次一致，不一致 → `bridge.version_incompatible` 拒绝服务。
- 无新增监听面：bridge 是按需拉起的短命客户端进程，不监听任何端口/套接字；
  interop 子进程以同一 Windows 用户令牌运行，named pipe「仅本用户」ACL
  语义不变。
- 完整规格见 [cross-subsystem.md](cross-subsystem.md)。

## 3. 会话令牌（D10）

- 解锁成功 → 守护进程签发**会话令牌**（高熵随机，如 256-bit），**随每次解锁轮换**。
- 后续所有请求必须携带令牌；令牌错误/过期 → `-32601` 风格错误（统一为
  `session.invalid`），客户端不得据此区分「库未解锁」与「令牌错」（防探测）。
- 令牌存放（**A1 取舍**，2026-08 规格矛盾裁决沿用）：CLI 每次调用是独立
  进程，令牌须经进程间传递才能跨命令复用解锁态——守护进程把令牌 hex 写入
  数据目录 `session.token`（unix 权限 0600；Windows 创建后显式收紧 DACL
  仅当前用户——尽力而为，收紧失败回落目录继承 ACL 并在 stderr 留痕，
  数据目录本身用户私有），**锁定/超时/守护进程退出即删除**，生命周期 =
  解锁窗口。
  风险面收窄到**同用户本地进程**——安全边界（补充拍板 #20 修订）：
  **产品接口面即边界**。令牌文件使同用户进程可复用解锁态（「跨命令复用
  解锁态」与 bridge 跨子系统复用桌面解锁态均为既定特性，#71/#74/#77 据此
  定案，补充拍板 #15），但**令牌 = 认证 ≠ 授权**：持令牌只保证能发起请求，
  **值的披露是授权事件**（读规则命中或弹窗批准，见
  [authorization-gate.md](authorization-gate.md) §8，拍板待实现）；绕过
  产品接口的同用户原生攻击（调试器/内存注入/键盘钩子等）在边界外，如实
  声明。「令牌仅存于客户端进程内存、不落盘」的形态（#68 选项 2）降级为
  观望：dispatch 层值裁决落地后，被盗令牌的残值只剩元数据与规则范围内的
  值，仅在元数据泄露被认为不可接受时再议。
- 锁定/超时/守护进程退出 → 令牌立即失效。

## 4. 方法与最小字段原则（D10）

| 方法 | 说明 | 返回（最小字段） |
|------|------|------------------|
| `vault.status` | 解锁态、**库是否已初始化**（M2.5 首启门控：无库 → 初始化向导）、同步水位、版本、审计锚点状态（`auditAnchorOk`，可选；issue #75，见 [audit.md](audit.md) §3.2） | 布尔 ×3 + 水位戳 |
| `vault.init` | 建库：设主密码（**至少 8 位**，弱密码 → `vault.weak_password`）+ 生成恢复码/信封；已存在库 → `vault.exists` | 恢复码（仅展示一次） |
| `vault.unlock` | 主密码解锁 | 会话令牌 |
| `vault.lock` | 立即锁定 | 无 |
| `vault.recover` | 恢复：恢复码 + 新主密码（重置主密码，数据保留） | 新恢复码（仅展示一次） |
| `item.list` | 索引（解密态最小字段） | id/name/type/revision/deleted |
| `item.get` | 单条（M2.9 值裁决：桌面直调豁免；socket 走**读规则 → 弹窗 → 拒绝**三层，未命中且无批准 → `authz.denied`（-32017）） | 完整解密条目 |
| `item.put` / `item.delete` | 写 | 新 revision |
| `item.export` | 导出 file 条目附件（整包下载；M2.9：**恒弹窗**，任何规则不豁免；headless 无 GUI → `authz.denied`） | 名称/MIME/大小 + base64 数据 |
| `sync.trigger` / `sync.poll` | 同步控制 | 变更摘要（不返回内容） |
| `authz.evaluate` | 授权门判定（M2）；`channel` 枚举 `cli` \| `desktop` \| `wsl-bridge`（跨子系统桥，补充拍板 #14，审计如实记录）。锁定态一体化（#67/补充拍板 #19）：库锁态 + 桌面审批界面在场 → 走临时解锁+本次授权一次交互（§4.1 锁定态）；headless 锁态 → fail-closed `session.invalid` | 允许/拒绝 + 最小 env 集 |
| `approval.result` | 客户端回传审批结果（M2；`approval.request` 已移除，语义并入 `ApprovalChannel::open`）。**仅桌面内嵌直调可提交**——socket/pipe 连接 → `channel.forbidden`（-32014）；params 含 `challenge`（`authz.request` 帧下发的一次性应答值，错值 → `accepted=false` 且条目保留；#72/#78 / 补充拍板 #16）；锁定态一体化待审+allowed 时含可选 `masterPassword`（守护进程临时解锁，§4.1） | accepted（是否接受） |
| `rule.add` / `rule.list` / `rule.remove` | 规则管理（M2，决策 #6；M2.9 起规则含 `capability`：`inject`（注入，缺省）\|`read`（读值，command 恒空串、keys=可读条目名），能力不互授） | 规则 / 规则列表 / 无 |
| `audit.list` | 审计查询 | 事件（无密钥值） |
| `audit.verify` | 校验审计 HMAC 链 | 已验证事件数 |
| `subscribe` | 推送通道订阅（M2；连接转入流模式，收 JSON-RPC notification 帧，决策 #3 A）。来源标签：桌面壳为进程内直调订阅，socket 流连接为普通订阅——后者**不计入审批界面判定、也收不到 `authz.request` 帧**（#72/#78：帧内 challenge 是审批应答凭据，只走桌面通道）。**锁定态订阅**（#67）：desktop 来源允许锁态订阅（推送目标注册，桌面直调无需会话令牌；socket 订阅照旧要求有效会话），使锁态 `authz.request` 帧到达 GUI；帧无密钥值，不泄露明文 | 无 |

- **最小字段原则**：IPC 响应只包含调用方被授权的最小已解密字段——例如
  `authz.evaluate` 只返回「被批准命令的 env 变量」，绝不返回整库内容
  （D10 原文：环境变量只注入被批准命令）。
- **错误码**：`vault.init` 的弱密码（`vault.weak_password`）与已存在库
  （`vault.exists`）错误码不同，但 UI 层统一文案不区分（防探测语义同
  §3 的 `session.invalid`）；`vault.recover` 的新主密码同策略。

### 4.1 锁定态一体化审批（#67，补充拍板 #19）

- **锁定态解除 + 本次授权一次交互**：库锁定 + 桌面审批界面在场时，锁态
  `authz.evaluate` 广播 `authz.request`（帧带 `needsUnlock=true`）→ 桌面弹窗
  同时收集主密码（身份确认）与 Allow/Deny（行为授权）；headless →
  fail-closed `session.invalid`。详见 [authorization-gate.md](authorization-gate.md) §5.1。
- **`authz.request` 帧扩展**：`needsUnlock`（bool）标注锁定态一体化审批（弹窗
  须收集主密码），缺省 false。M2.9 值披露：`kind`（`inject`\|`read`\|`export`）
  标注审批类型（弹窗按形态渲染），缺省 `inject`；`kind=export` 时带
  `exportMeta`（`name`/`mime`/`size`，数据包规模，不含数据本身）。
- **`approval.result` 扩展**：可选 `masterPassword`——仅 `needs_unlock` 待审
  条目 + `allowed` 决策时使用并校验；守护进程以其做**临时解锁**（AuthGuard
  限流照常），错误主密码计失败计数并以错误响应退回弹窗（条目保留可重试）。
- **临时解锁安全边界**：允许决策后守护进程以主密码临时解锁 vault 内存态，
  仅供本次注入解析 env + 审计签名；**不签发会话令牌 / 不写 `session.token` /
  不置 `shared.vault`**——vault 保持锁定，临时态随 finalize 结束销毁，不产生
  `item.*` 全量读能力（#65 配套）。

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
