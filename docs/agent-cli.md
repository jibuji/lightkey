# Agent 集成：`lk` CLI 机器可读输出契约（agent-cli）

- 状态：已实现（issue #103；父 epic #102 PR1）
- 关联：[cli.md](cli.md)（命令语义）· [ipc.md](ipc.md)（错误码）·
  [authorization-gate.md](authorization-gate.md)（授权门）·
  [value-disclosure.md](value-disclosure.md)（值披露裁决）·
  [cross-subsystem.md](cross-subsystem.md)（WSL 桥）
- 读者：把 `lk` 包装成 skill 的作者（Claude Code / Codex 等）与脚本作者。
  本文是输出契约的**唯一权威**：命令矩阵、JSON 形状、错误分类→建议动作、
  锁定/无 UI 行为。写 skill 以本文为准，不靠逆向试错。

## 1. 总则

- `--json` 是**全局标志**（`lk <cmd> --json`）：stdout 只承载机器可读输出，
  人类文案（含警告、审批提示）一律走 stderr。
- 退出码语义不变：`0` 成功；`1` 业务失败（拒绝/超时/冲突）；`2` 用法错误
  （含 `item get --name` 重名歧义）。
- **stdout 永不携带密钥值**（inject 允许路径零输出；`item get --json` 例外
  是显式取值命令，见 §6）。
- 匹配键优先级：`error` 名为主键（CLI 内唯一），`code` 只作兜底。

## 2. inject 优先指引（skill 作者必读）

**任务允许时优先 `lk inject`，值不进 agent 上下文。**

- `lk inject --keys <name...> -- <cmd...>` 把值注入**子进程环境变量**，
  值不落 stdout/日志/审计，agent 自身上下文里只有 key 名。
- 仅当值必须**被读取**（如要填进 HTTP 请求体、要拼进配置文件）才用
  `item get`，且取回的值同样不应回显到对话/日志。
- 常见判断：跑构建/发布/登录命令 → inject；分析值内容 → item get（受
  读规则 + 弹窗裁决，见 §7）。

## 3. 命令矩阵

| 命令 | `--json` 成功形状（stdout） | 失败行为（`--json`） |
|------|---------------------------|---------------------|
| `lk status --json` | `{"unlocked":…,"version":…,"syncWatermark":…,"target":"local"\|"bridge"}` | 错误对象（§5） |
| `lk unlock --stdin --json` | 纯文本「已解锁」（成功输出未 JSON 化） | 错误对象 |
| `lk item list [--type T] [--name 子串] --json` | **裸数组** `[{id,name,type,revision,deleted},…]`（§4.2） | 错误对象 |
| `lk item get <id> --json` | 条目对象（含值，按类型分形） | 错误对象（`authz.denied` 见 §6） |
| `lk item get --name <名> --json` | 同上（先经 item.list 解析 id，裁决路径与 id 版完全一致） | 错误对象；重名 → `item.name_ambiguous` exit 2 |
| `lk item export <id> --output <p> --json` | 人类文案（附件写文件，不 JSON 化） | 错误对象（export 恒弹窗，headless 必拒） |
| `lk rule add … --json` | 规则对象 | 错误对象 |
| `lk rule list --json` | 规则数组 | 错误对象 |
| `lk rule remove <id> --json` | 人类文案 | 错误对象 |
| `lk inject --keys … -- <cmd> --json` | **零输出**（退出码 = 子进程退出码） | 裁决拒绝 → `{"allowed":false,"reason":…}`（§4.3）；RPC 失败 → 错误对象 |
| `lk sync --json` | 同步摘要对象 | 错误对象 |
| `lk config get <key> --json` | `{"<key>": "<value>"}` | 错误对象 |

**过滤（`item list`，CLI 侧完成、协议不变）**：

- `--type <login|note|secret|file>`：按类型精确过滤；
- `--name <子串>`：按条目名**子串**过滤（注意：与 `item get --name` 的
  **精确匹配**语义不同）；
- 二者可组合；`--type` 非法值 → clap 用法错误 exit 2。

**`item get --name <名>`**：

- 经 `item.list` 按名**精确**解析 id（墓碑条目不参与），随后与位置 id 版
  走**完全相同**的 `item.get` 值披露裁决（读规则 → 弹窗 → 拒绝）；
- 与位置 `<id>` 互斥（同给 → clap exit 2）；
- 重名（≥2 条存活同名）→ exit 2 + `item.name_ambiguous`（§5），
  message 含全部候选 id，向用户澄清后再取。

## 4. JSON 形状（钉死）

### 4.1 失败错误对象（所有命令，RPC/传输/桥级失败）

```json
{"ok":false,"error":"authz.denied","code":-32017,"message":"…人类文案…"}
```

| 字段 | 类型 | 语义 |
|------|------|------|
| `ok` | bool | 恒 `false` |
| `error` | string | CLI 侧错误分类名，**CLI 内唯一**（§5 全表；同码不同源已消歧） |
| `code` | number | JSON-RPC 错误码兜底；CLI 本地失败（无服务端码）为 `0`；未知服务端码归 `error:"other"` 且 `code` 保留原始值 |
| `message` | string | 与 stderr 人类文案相同（可直接转述给用户） |

人类文案照旧输出到 stderr（`lk: <文案>`）；字段顺序 `ok,error,code,message`。

### 4.2 `item list --json`：裸数组

stdout 直接是数组（不包对象），元素为条目摘要：

```json
[
  { "id": "00000000-…", "name": "API_KEY", "type": "secret", "revision": "…", "deleted": false }
]
```

`--type`/`--name` 过滤在数组返回**前**完成（不把整库名单倒进上下文）。

### 4.3 `inject --json` 拒绝对象

```json
{"allowed":false,"reason":"no_ui"}
```

只含 `allowed`/`reason` 两字段，不携带 env（值不落 stdout）。`reason` 枚举
（与守护进程 `DenyReason` 一致，共 7 个）：

| reason | 语义 | skill 建议动作 |
|--------|------|---------------|
| `unknown_starter` | 无法确定启动者（进程链回溯失败） | 从正常终端/项目目录内重试；仍失败则放弃并报告 |
| `no_cwd` | 无法确定工作目录 | 同上；macOS 见 §8 注记 |
| `missing_keys` | 请求的 key 无法满足（不存在或不可注入；仅支持 secret 类型条目名，防枚举不区分） | 用 `item list --type secret --name <子串>` 核对条目名 |
| `rule_corrupt` | 规则库损坏 | 提示用户在桌面端检查规则库 |
| `no_ui` | 无审批界面（桌面端未运行或通知订阅未建立） | 提示用户启动 LightKey 桌面端后重试 |
| `rejected` | 用户拒绝 | 尊重决定，勿自动重试 |
| `timeout` | 审批超时（30s 默认拒绝） | 提示用户在场时重试 |

注意：**锁态 headless inject** 走的是 RPC 级失败（`session.invalid` 错误
对象），不是本表——两级失败形状不同（§1）。

## 5. 错误分类全表（error 名 → 建议动作）

`error` 名是主匹配键。同码不同源（如 -32014）已按来源消歧为不同名：

| error | code | 来源 | 建议动作 |
|-------|------|------|---------|
| `session.invalid` | -32002 | 守护进程 | 提示用户**解锁桌面端**（或 `lk unlock`）后重试 |
| `authz.denied` | -32017 | 值披露裁决 | 提示用户在弹窗中批准；或经用户同意后 `lk rule add <projectDir> --read --name <规则名> --keys <条目名>` 预授权 |
| `vault.invalid` | -32001 | 守护进程 | 主密码错误或库未初始化（文案统一防探测）；提示用户核对 |
| `item.not_found` | -32004 | 守护进程 / `--name` 无命中 | 用 `item list --name <子串>` 查正确名 |
| `item.name_ambiguous` | 0（exit 2） | CLI 本地 | `--name` 重名歧义；message 含候选 id，向用户澄清或改用 id |
| `item.conflict` | -32003 | 守护进程 | CAS 冲突；重新读取条目后再编辑 |
| `item.limit` | -32005 | 守护进程 | 超出限制（如附件 >50MB） |
| `rate.limited` | -32006 | 守护进程 | 等待 message 中给出的秒数后重试 |
| `vault.exists` | -32007 | 守护进程 | 库已存在；重置需 `lk init --force`（破坏性，须用户确认） |
| `vault.weak_password` | -32013 | 守护进程 | 主密码至少 8 位 |
| `sync.not_configured` | -32009 | 守护进程 | 先 `lk config sync set <url>` |
| `sync.storage` | -32010 | 守护进程 | 同步存储端错误；检查远端/凭据 |
| `sync.data_anomaly` | -32011 | 守护进程 | 同步数据异常，本轮已放弃；勿盲目重试 |
| `sync.credentials` | -32012 | 守护进程 | 同步凭据不可用；重新配置 |
| `channel.forbidden` | -32014 | 守护进程（transport 语境） | 该操作只接受桌面内嵌直调；skill 不应触达（到达即协议误用） |
| `bridge.no_daemon` | -32014 | bridge（WSL 桥语境） | Windows 桌面应用未运行（或管道不可达）；提示用户启动桌面端 |
| `bridge.version_incompatible` | -32015 | bridge | 桌面应用与本 CLI 协议版本不一致；重装桌面应用 |
| `bridge.io` | -32016 | bridge | 桥中继 I/O 失败；重试或检查安装 |
| `other` | 原始码 | 守护进程 | 未知服务端码；以 `code` 兜底分支，`message` 转述用户 |
| `transport` | 0 | CLI 本地 | 连不上守护进程/桥探测失败；提示用户启动桌面端或检查安装 |
| `bad_response` | 0 | CLI 本地 | 响应帧非法；属异常，建议报告 |

- **-32014 双义消歧**（error 名的主键地位由此确立）：daemon 错误帧
  message=`channel.forbidden`（socket 通道提交了桌面专属方法）vs bridge
  错误帧 message=`bridge.no_daemon`（中继找不到 Windows 守护实例）——CLI
  按消息分型，skill 只看 `error` 名即可。
- **覆盖边界**：clap 用法错误（参数缺漏/冲突/非法值，exit 2）与 CLI 本地
  输入校验失败（如密码为空、附件文件读取失败）仍为 stderr 文案 + 退出码，
  **不产生 JSON 对象**；stdout 为空即属此类。

## 6. 锁定 / 无 UI 行为表

当前实现（M2.95，补充拍板 #22/#23：规则管理审批门 + 读通道一体化解锁已落地）：

| 命令 | 解锁态 + 桌面 UI 在场 | 解锁态 headless（无 UI） | 锁定态 + 桌面 UI 在场 | 锁定态 headless |
|------|----------------------|--------------------------|----------------------|-----------------|
| `lk inject` | 无规则 → 审批弹窗（30s，默认拒绝） | 无规则 → `{"allowed":false,"reason":"no_ui"}` | **一体化弹窗**（主密码 + Allow/Deny 一次交互，#67/M2.8） | `session.invalid` 错误对象 |
| `lk item get`（id 或 --name） | 无读规则 → 读值弹窗 | `authz.denied` | **一体化弹窗**（主密码 + 解锁并允许一次交互，#23/M2.95） | `session.invalid` |
| `lk item export` | **恒弹窗**（读规则也不豁免） | `authz.denied` | **一体化弹窗**（主密码 + 解锁并允许一次交互，#23/M2.95） | `session.invalid` |
| `lk item list` | 正常（令牌门，元数据不裁决） | 正常 | `session.invalid` | `session.invalid` |
| `lk rule add` / `lk rule remove` | **审批弹窗**（规则的建立与撤销都是授权事件，#22/M2.95；30s 超时默认拒绝；desktop 直调豁免） | `authz.denied`（headless 无 UI，除非 daemon 以 `LIGHTKEY_E2E_AUTO_APPROVE=rule` 启动；测试专用） | `session.invalid` | `session.invalid` |
| `lk rule list` | 正常（令牌门，只读元数据） | 正常 | `session.invalid` | `session.invalid` |
| `lk status` | 正常（无需令牌） | 正常 | 正常（报告 `unlocked:false`） | 正常 |

- 解锁态的判定前提：守护进程持有有效会话令牌（`lk unlock` 或桌面端解锁后
  自动落盘）。
- 锁定态下**一切值披露都要先解锁**（inject 的一体化弹窗除外）；
  `session.invalid` 的建议动作固定为「解锁桌面端后重试」。
- **写门（M2.97 规划中，未上线）**：`lk item add / edit / delete` 当前仍为
  令牌门；落地后按 [write-gate.md](write-gate.md) 判定矩阵执行——
  create/update 命中写规则静默、未命中弹窗、headless `authz.denied`；
  delete 恒弹窗任何规则不豁免；锁态 `session.invalid`。
  本表其余行不受写门影响。

## 7. 值披露与 inject 的裁决语义（速查）

- `item get`：读规则（`rule add --read`）命中 → 静默放行；未命中 → 桌面
  弹窗；拒绝/超时/无 UI → `authz.denied`（-32017，统一文案防探测）。
- `item export`：恒弹窗，无规则豁免路径。
- `inject`：注入规则白名单（projectDir + command + keys）→ 静默放行；
  否则弹窗；拒绝以 `{"allowed":false,"reason":…}` 呈现（§4.3）。
- 读规则与注入规则**能力不互授**（read 规则不授权 inject，反之亦然；
  M2.97 写门规划再扩 write——三能力两两不互授）。
- 写命令（M2.97 规划中）：`item add/edit` 走写规则/弹窗/拒绝三层（update
  双向名称约束），`item delete` **恒弹窗**任何规则不豁免；拒绝统一复用
  `authz.denied`（-32017，CLI 按命令语境渲染文案）。

## 8. 平台注记

- **macOS cwd fail-closed**：macOS 的对端 cwd 解析尚未实现
  （authorization-gate.md §2 已知限制）——macOS 上 `lk inject` 及一切依赖
  cwd 匹配的裁决会 fail-closed 拒绝（`unknown_starter`/`no_cwd`），
  属预期行为而非故障。
- **WSL 桥**：WSL 内 `lk` 经 `lk.exe bridge` 连 Windows 桌面守护实例，
  错误名带 `bridge.*` 前缀（§5）；bridge 连接目标行输出在 stderr。

## 9. 退出码速查

| 退出码 | 含义 | `--json` 下的 stdout |
|--------|------|---------------------|
| 0 | 成功 | 命令各自的成功形状（§3） |
| 1 | 业务失败 | 错误对象（§4.1）或 inject 拒绝对象（§4.3） |
| 2 | 用法错误 / `--name` 重名歧义 | 歧义 → 错误对象（`item.name_ambiguous`）；clap 用法错误 → 仅 stderr |
