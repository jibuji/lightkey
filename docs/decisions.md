# Wayfinder 决议集（2026-08-15）

本文档记录 2026-08-15 四轮 grilling 中船长逐条拍板的决议。**本仓库的规格文档
以本决议集为唯一权威来源**；实现时如发现规格与决议矛盾，以决议为准并上报
needs-decision，不得自行变更。

## 背景（已定）

- 路线：**从零自研**——把 Bitwarden 当作“技术规格书”照抄设计（抄设计不抄代码，
  不 fork、不用 Bitwarden/Vaultwarden 当底座）。
- 许可：**客户端全开源（MIT）**；服务端（如未来有）不开源；付费暂缓。
- 本仓库：`jibuji/lightkey`（private），no-mistakes 已 init。

## 决议项 → 规格映射

| # | 决议（原文要点） | 落盘位置 |
|---|------------------|----------|
| D1 | V1 MVP 交付 = 核心库 + CLI（`lk`）+ 桌面应用；浏览器扩展是 M3（V1 之后）；本任务产出可开工实施 spec（含前端设计） | [architecture.md](architecture.md)、[milestones.md](milestones.md) |
| D2 | 技术栈：Tauri 2（Rust 核心 + React）；CLI 复用同一 Rust 核心；Windows + macOS 为验收平台，Linux 冒烟不阻塞 | [architecture.md](architecture.md)、[testing.md](testing.md) |
| D3 | 里程碑：M0 骨架+单机闭环 → M1 同步（BYO 变更发现 + CAS + 墓碑）→ M2 Agent 授权门 + 桌面端 → M3 浏览器填充 | [milestones.md](milestones.md) |
| D4 | 加密：vault 头随机 16B salt + KDF 参数 + 密文格式类型/版本号；Argon2id(m=64MiB,t=3,p=4) 派生主密钥；HKDF-SHA256 分叉数据加密/恢复信封/审计 HMAC 三密钥互不复用；原语刻意不同于 Bitwarden（AES-256-GCM，不用 CBC+HMAC） | [crypto.md](crypto.md) |
| D5 | 数据模型：条目级密文 blob + 加密索引 + revisionDate 增量同步 + 软删除墓碑（30 天延迟硬删）+ 乐观并发（CAS，整条目 last-write-wins）；条目 schema 参照 Bitwarden login/secureNote 映射；附件每附件独立密钥 + 1 MiB 流式分块；自描述密文格式（含类型版本号） | [data-model.md](data-model.md) |
| D6 | 元数据可见性：条目 blob 与索引/清单文件全部加密；存储端只见密文文件 + 文件名时间戳（零知识彻底） | [data-model.md](data-model.md)、[sync.md](sync.md) |
| D7 | 变更发现：加密索引 + 轮询（默认 60s，可配 15s~24h）；无推送、无中间态加载、静默轮询；发现变更才下载条目；BYO（WebDAV/S3 无服务器）无推送下的变更发现是方案 A 在 BYO 场景的真实代价，写入文档 | [sync.md](sync.md) |
| D8 | Agent 授权门：三层 = 默认拒绝 → 规则白名单（规则入库、按项目目录绑定，agent 只能看到被授权 key 名）→ 弹窗审批（30 秒超时默认拒绝）；启动者判定 = 进程链回溯 + 工作目录；规则库写入 = `lk rule add` CLI + 桌面规则管理页；规则文件 vault 内加密、按项目目录绑定；不开放手动改加密文件；审批通道抽象成接口（本地/远程可切换，远程=未来服务端付费点，P1 不做）；`lk inject` = 给具名命令注入环境变量；密钥只注入被批准具名命令的进程环境，不进模型对话环境 | [authorization-gate.md](authorization-gate.md) |
| D9 | 恢复机制：恢复码 = 高熵 40 字符备份凭证（保存一次、不记忆）；恢复信封 = 恢复码 + Argon2id 派生信封密钥加密主密钥副本，可随库进 BYO 云（不破坏零知识）；恢复仅需恢复码 + 新设主密码；三通道全丢 = 数据不可恢复（诚实文案）；已信任设备宽限期（借鉴 1Password 生物识别宽限，如 Windows Hello） | [recovery.md](recovery.md) |
| D10 | 本地 IPC：Unix domain socket / Windows named pipe + JSON-RPC 2.0；会话令牌随解锁轮换；lk 常驻守护进程持解锁态，密钥只存在于守护进程内存；CLI/桌面/浏览器扩展（Native Messaging，M3）统一走守护进程；IPC 响应只含已解密最小字段（如环境变量只注入被批准命令）；锁屏/超时自动锁定 | [ipc.md](ipc.md) |
| D11 | 审计日志：默认永久保留，后续允许用户设置滚动保留时间；事件 = 时间戳 + 启动者进程 + 目标程序 + 命令摘要 + 结果（允许/拒绝/超时）+ 审计 HMAC（防篡改）；元数据明文、密钥值永不明文；本地追加式 | [audit.md](audit.md) |
| D12 | 浏览器填充通道（M3，spec 含协议但实现 V1 后）：扩展不持钥，Chrome 官方 Native Messaging 走桌面已解锁会话取凭据填充；扩展内存无密钥；桌面未运行/锁定时填充置灰 + 快速解锁弹窗缓解；剪贴板 30s 自动清除、只填充用户主动点击的输入框 | [browser-fill.md](browser-fill.md) |
| D13 | 测试三层：Rust 核心单元+属性测试（加密往返/CAS 冲突/墓碑收敛）→ E2E 双客户端冲突合并 → 安全专项（授权门绕过尝试、审计篡改检测）；CI GitHub Actions；测试 fixture 密钥不进仓库 | [testing.md](testing.md) |
| D14 | 前端设计（Q3 含）：两份 = ① 设计规范（tokens/色彩/组件库/解锁与条目交互流程）② 高保真单页原型（可交互、可预览截图评审）；工具链 = 自研 UI 设计工具 + agent_browser 预览截图 + doubao-seed-2.1-turbo 视觉评审 + lavish-axi 船长评审面（D1/D2 已定，不装第三方设计 skill） | [design/spec.md](design/spec.md)、[design/prototype](design/prototype/) |
| D15 | 开源/商业：暂不考虑付费；免费版不做条目数限制；付费边界（官方签名构建/远程审批中继等）推迟到验证后再议 | [architecture.md](architecture.md)（非目标） |

## 需新决策的事项（当前为空）

无。如实现中发现规格空白或矛盾，在本节登记并上报 needs-decision。
