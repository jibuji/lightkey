# `lk` CLI 命令参考（cli）

- 状态：已拍板（命令集为规格；行为随里程碑实现）
- 关联：[ipc.md](ipc.md)（守护进程）· [milestones.md](milestones.md)

## 0. 总则

- `lk` 是 LightKey 的命令行入口；所有命令经**守护进程**执行（自动拉起，
  见 [ipc.md](ipc.md)）。
- 退出码：`0` 成功；`1` 业务失败（拒绝/超时/冲突）；`2` 用法错误（骨架占位
  现统一返回 2，实现后按此约定）。
- 命令树已声明于 `crates/lk-cli/src/main.rs`，下表为完整语义。

## 1. 库生命周期

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk init` | 初始化新库：设置主密码、生成恢复码（仅展示一次）与恢复信封 | M0 |
| `lk unlock` | 解锁库（连接守护进程，签发会话令牌） | M0 |
| `lk lock` | 锁定库（擦除内存密钥，失效令牌） | M0 |
| `lk status` | 解锁态、同步水位、版本、连接目标（本地 daemon / Windows 桌面守护实例经 bridge，补充拍板 #14） | M0 |
| `lk recover` | 恢复：恢复码 + 新主密码（重置主密码，数据保留） | M0 |

## 2. 条目

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk item list` | 列出条目（最小字段） | M0 |
| `lk item get <id>` | 取单条（完整解密字段） | M0 |
| `lk item add` | 新建条目（四类：login / note / secret / file；交互或 flag，见 [design/spec.md](design/spec.md) §4） | M0 |
| `lk item edit <id>` | 编辑条目（CAS，见 [data-model.md](data-model.md) §4） | M0 |
| `lk item delete <id>` | 软删除（墓碑，30 天硬删） | M0 |
| `lk item copy <id> <field>` | 复制字段到剪贴板（30s 自动清除，见 [browser-fill.md](browser-fill.md) §2 同款行为） | M0 |
| `lk item export <id> --output <path>` | 导出 file 条目附件到本地文件 | M0 |

## 3. 同步

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk sync` | 触发一次同步（轮询 + CAS 上传） | M1 |
| `lk config sync set <url>` | 配置 BYO 存储（WebDAV/S3）与轮询间隔（15s~3600s（1h），默认 60s；上限 1h 见补充拍板 #8，范围 15s~3600s 已校验、超限拒绝）；位置参数只接受存储 URL，凭据交互式提示输入（不回显），也可 `--credentials-file <path>` 或 `--stdin` 导入，不接受凭据明文位置参数 | M1 |
| `lk config get <key>` | 读取配置 | M1 |

## 4. Agent 授权门

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk rule add <projectDir> <command> --name <name> <keys...>` | 新增白名单规则（入库加密） | M2 |
| `lk rule list` | 列出规则（最小字段） | M2 |
| `lk rule remove <id>` | 删除规则 | M2 |
| `lk inject --keys <name...> -- <command...>` | 给具名命令注入被批准 env（三层模型，见 [authorization-gate.md](authorization-gate.md) §5；`--keys` 必需，且只可指名 **secret 类型条目**的名称——login/note/file 条目不支持注入，与「不存在」同样拒绝、不另行区分，不泄露库内 key 名单）。**值生命周期**：值会经 lk CLI 进程内存传递一次（已做 zeroize 擦除 + 防 core dump/WER 加固，见 [decisions.md](decisions.md) 补充拍板 #17），仅排除 stdout/日志/审计；不防**同用户调试器**（同用户进程互信在防护边界外，补充拍板 #15）。**锁定态**（#67）：vault 锁定 + 桌面审批界面在场 → CLI 触发 GUI 弹「临时解锁 + 本次授权」一次性交互（CLI 侧等待决策；见 [authorization-gate.md](authorization-gate.md) §5.1）；GUI 不在运行（headless）→ fail-closed `session.invalid`（CLI 仍提示先解锁） | M2 |

## 5. 审计与守护进程

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk audit [--tail <N>] [--verify]` | 查看审计日志（只读；无密钥值；`--tail` 最近 N 条、`--verify` 校验 HMAC 链 + **交叉核对文件外锚点**，见下方 §5.0） | M0 |
| `lk daemon` | 以守护进程方式常驻（解锁态、密钥仅内存；由客户端自动拉起，也可手动前台运行） | M0 |
| `lk bridge` | （Windows）stdio 中继：stdin 逐行读 JSON-RPC 帧 → named pipe → stdout 回写，一进程一请求后退出；不做业务解析（除版本校验外原样透传）；错误码 `bridge.no_daemon` / `bridge.version_incompatible` / `bridge.io`，退出码非 0。随桌面包安装，供 WSL 侧 Linux `lk` 经 interop 调用 | M2.75 |

## 5.0 `lk audit --verify` 截断检测（issue #75）

- 除原有 HMAC 链校验外，`--verify` 还会**交叉核对文件外锚点**（平台安全存储 /
  降级侧写，见 [audit.md](audit.md) §3.2）。
- **截断检测**：链比可信锚点短（tail 被抹）、链与锚点 ordinal 相同但最后一条
  事件的 HMAC 不一致（锚定事件被换/伪造）、或锚点缺失（平台与侧写都没有）——
  上述任意情形都打印「截断检测（truncation detected）」并**退出非零**。
- 锚点落后于链尾（锚点后追加的事件，不是截断）：正常通过，输出里提示锚点
  覆盖范围；平台 keychain 不可用已降级到侧写时，会在输出里标注「防篡改能力
  减弱」警告，但不影响退出码（链仍完整可证明）。

## 5.1 跨子系统桥环境变量（补充拍板 #14，M2.75）

- `LIGHTKEY_BRIDGE`：
  - `off` — 强制本地 daemon（逃生口）；
  - `<路径>` — 强制用该 `lk.exe` 当中继（跳过探测；Windows 路径或
    `/mnt/c` 形式均可）；
  - 未设置 — **auto 默认**：检测到 WSL（`WSLInterop` 存在）→ 自动探测
    bridge；非 WSL（Linux/macOS 原生）→ 本地 daemon。
- `LIGHTKEY_BRIDGE_HOME` — 多用户/自定义盘时显式指定 Windows 侧数据目录。
- 探测失败**分型**：Windows 侧装了 LightKey 但 bridge 连不上（lk.exe 缺失/
  管道不通/版本不兼容）→ 明确报错，绝不静默回落本地（防「空库错觉」）；
  Windows 侧没有 lightkey 数据目录 → 静默走本地 daemon。
- 目标可见性（auto 默认的安全补偿）：每次经 bridge 执行命令向 stderr 打一行
  「→ 经 bridge 连接 Windows 桌面守护实例（版本 x.y）」；`lk status` 输出
  连接目标字段。
- 配置命令与状态行（补充拍板 #14 裁定）：bridge 后端下 `lk config`
  （`get` / `sync set`）与 `lk status` 的同步配置行读写 **Windows 侧**数据目录
  的 `config.json`（定位与读会话令牌同源，`LIGHTKEY_BRIDGE_HOME` 显式指定时
  以其为准），本地后端行为不变；bridge 模式 `status` 同步行标注
  「（Windows 桥接）」。凭据仍存本机钥匙串——Windows 守护实例读取的是
  Windows 侧钥匙串，WebDAV/S3 凭据需在桌面应用或 Windows 侧 `lk.exe` 配置。

## 6. 行为约束

- 交互式敏感输入（主密码、存储凭据）不回显；`lk unlock` 与
  `lk config sync set` 支持 `--stdin` 管道（供脚本，明确警示），后者另支持
  `--credentials-file` 文件导入。
- 所有敏感输出（密码/令牌）默认不落 stdout 日志；`--json` 输出仅用于机器消费，
  同样遵循最小字段。
- 错误信息不区分「未解锁/令牌错」（[ipc.md](ipc.md) §3）。
- 跨子系统桥（M2.75）：`lk`/`lk.exe bridge` 的 stdio 一律按原始字节读写，
  禁止文本模式转换（UTF-8 与换行保真）；主密码在 WSL 终端交互输入不回显，
  会话令牌仅存 `lk` 进程内存（D10 不变）。详见
  [cross-subsystem.md](cross-subsystem.md)。
