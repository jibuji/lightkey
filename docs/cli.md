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
| `lk status` | 解锁态、同步水位、版本 | M0 |
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
| `lk inject --keys <name...> -- <command...>` | 给具名命令注入被批准 env（三层模型，见 [authorization-gate.md](authorization-gate.md) §5；`--keys` 必需） | M2 |

## 5. 审计与守护进程

| 命令 | 语义 | 里程碑 |
|------|------|--------|
| `lk audit [--tail <N>] [--verify]` | 查看审计日志（只读；无密钥值；`--tail` 最近 N 条、`--verify` 校验 HMAC 链） | M0 |
| `lk daemon` | 以守护进程方式常驻（解锁态、密钥仅内存；由客户端自动拉起，也可手动前台运行） | M0 |

## 6. 行为约束

- 交互式敏感输入（主密码、存储凭据）不回显；`lk unlock` 与
  `lk config sync set` 支持 `--stdin` 管道（供脚本，明确警示），后者另支持
  `--credentials-file` 文件导入。
- 所有敏感输出（密码/令牌）默认不落 stdout 日志；`--json` 输出仅用于机器消费，
  同样遵循最小字段。
- 错误信息不区分「未解锁/令牌错」（[ipc.md](ipc.md) §3）。
