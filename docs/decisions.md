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
| D2 | 技术栈：Tauri 2（Rust 核心 + React）；CLI 复用同一 Rust 核心；验收平台 = Windows（原「Windows + macOS 双验收」的 CI 部分被补充拍板 #4 替代，见下文） | [architecture.md](architecture.md)、[testing.md](testing.md) |
| D3 | 里程碑：M0 骨架+单机闭环 → M1 同步（BYO 变更发现 + CAS + 墓碑）→ M2 Agent 授权门 + 桌面端 → M3 浏览器填充 | [milestones.md](milestones.md) |
| D4 | 加密：vault 头随机 16B salt + KDF 参数 + 密文格式类型/版本号；Argon2id(m=64MiB,t=3,p=4) 派生主密钥；HKDF-SHA256 分叉数据加密/审计 HMAC 两密钥互不复用，恢复信封密钥由恢复码 + Argon2id 独立派生（2026-08-15 grilling 后补充拍板，见下文）；原语刻意不同于 Bitwarden（AES-256-GCM，不用 CBC+HMAC） | [crypto.md](crypto.md) |
| D5 | 数据模型：条目级密文 blob + 加密索引 + revisionDate 增量同步 + 软删除墓碑（30 天延迟硬删）+ 乐观并发（CAS，整条目 last-write-wins）；条目 schema 见四类存储类型定案（登录/笔记/密钥/文件，v2，补充拍板 #6）；附件每附件独立密钥 + 1 MiB 流式分块；自描述密文格式（含类型版本号） | [data-model.md](data-model.md) |
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
| D16 | 插件化落地 = 选项 A：TS/桌面/前端真 Cordis（@cordisjs/core 4.x）；Rust 核心保持单一 crate lk-core，按同一边界重组为 trait 服务 + 事件总线（模拟 Cordis 语义，不强行移植）；安全核心（加密/数据/同步/审计）留在 Rust 不重写为 TS；四层插件 A 数据平面 + B 能力域 + C 宿主 + D 前端 TS Cordis；事件总线 item.changed / session.unlocked / session.locked / authz.request / theme.changed / clipboard.copied（emit 为主，waterfall 仅用于 Rust 授权门三层短路，均硬编码安全流程）；数据驱动边界：应用数据（声明式装配契约）≠ 用户数据（严格分离），安全流程硬编码永不数据化，防 inner-platform；装配四层①存在②位置③数据源数据驱动、④组件内部 React 写死，槽位骨架宿主写死、槽位内组件有无/顺序数据驱动 | [plugin-architecture.md](plugin-architecture.md)、[milestones.md](milestones.md)、[architecture.md](architecture.md)、[design/spec.md](design/spec.md) |

## 需新决策的事项

### 已补充拍板（2026-08-15 grilling 后 · 来源：no-mistakes review）

1. **恢复信封密钥派生来源（裁定：选项 A，以 [recovery.md](recovery.md) 为准）**：
   恢复信封密钥 K_recovery 由**恢复码 + Argon2id 独立派生**，与主密钥无关；
   HKDF-SHA256 仅分叉两把密钥——数据加密密钥 K_data 与审计 HMAC 密钥 K_audit。
   恢复时仅凭**恢复码 + 新设主密码**即可取回主密钥副本。已修订
   [crypto.md](crypto.md) §2 分叉图（原 D4 其余内容仍然有效）。
2. **审计密钥轮换验证链（裁定：选项 A）**：切换审计密钥前，先用旧 K_audit
   签名一条「审计密钥轮换」事件（记录切换时间与新旧密钥标识），形成验证链：
   新密钥验证新事件，旧事件通过链条追溯到轮换签名，旧日志全程可验证；审计
   永久保留 + 防篡改语义不变。已修订 [recovery.md](recovery.md) §3 第 3 步与
   [audit.md](audit.md) §3.1（原 D11 其余内容仍然有效）。
3. **BYO 存储凭据输入形态（裁定）**：`lk config sync set` 改为交互式提示输入
   （不回显），并支持从文件/stdin 导入；命令行位置参数只接受存储 URL，不接受
   凭据明文。已修订 [cli.md](cli.md) §3 与 [sync.md](sync.md) §6。
4. **CI 收敛为 Windows 优先（裁定，替代 D2 的 CI 部分）**：船长本机为
   Windows WSL，Windows 是主开发测试平台；CI 只保留 Windows 全量检查
   （fmt / clippy / test / `cargo check --workspace`）与 ubuntu 上的前端构建，
   删除 macOS 与 Linux 桌面构建以加速。已修订 `.github/workflows/ci.yml`、
   [architecture.md](architecture.md) §2/§4 与 [testing.md](testing.md) §3
   （原 D2 的「Windows + macOS 双验收」CI 部分不再适用；验收平台 = Windows）。
5. **加密索引范围扩展（裁定：选项 A，来源：no-mistakes document 阶段发现）**：
   加密索引从「条目最小索引」扩展为「vault 对象最小索引，覆盖条目与规则」
   （`id`/`revisionDate`/`type`，`type ∈ item/rule`，`deleted` 覆盖条目与规则）；
   规则经同一索引/轮询路径发现与增量同步，与
   [authorization-gate.md](authorization-gate.md) §4「规则随库同步」声明一致。
   规则删除态存于加密索引（规则体不含 `deleted`/`revision` 字段，删除态由索引
   自描述并以墓碑文件承载）。2026-08-22 船长裁定：规则删除统一走软删/墓碑/
   30 天硬删，与条目同路径。已修订 [data-model.md](data-model.md) §6 与
   [authorization-gate.md](authorization-gate.md) §4（原 D5/D8 其余内容仍然有效）。
6. **存储类型定案 v2（船长 2026-08-15 定案，四类）**：
   原 D5 的「条目 schema 参照 Bitwarden login/secureNote 映射」不再适用，
   改为四类存储类型：**登录 login**（账号+密码+网址）、**笔记 note**
   （名称+Markdown 文本，轻量编辑+语法高亮、无预览，非旧版「名称+备注」空壳）、
   **密钥 secret**（值+用途/备注+可选过期时间）、**文件 file**
   （名称+备注+大小+类型+加密附件，元数据+附件独立加密存储，单文件 ≤50MB）。
   统一原则：所有类型（含笔记、文件）一律**真加密存储**（零知识）；
   **已砍「收藏 favorite」字段**（用途模糊，V1 不提供）。
   已修订 [data-model.md](data-model.md) §3、[cli.md](cli.md) §2 与
   [design/spec.md](design/spec.md) §4（原 D5 其余数据模型内容仍然有效）。
7. **存储端文件名无时间戳（裁定：选项 A，来源：A1 规格矛盾裁决）**：
   D6 的「文件名时间戳」表述不适用于实现——文件名纯 UUID 无时间戳，
   同步排序依据加密索引内 revisionDate（[data-model.md](data-model.md) §6），
   文件名带时间戳会向存储端泄漏修改时间，违反零知识彻底。
   已修订 [data-model.md](data-model.md) §2、[sync.md](sync.md) §1、
   [crypto.md](crypto.md) §4.3 与 [milestones.md](milestones.md) M1
   （原 D6 其余内容仍然有效）。

### 已补充拍板（2026-08-22 · 来源：前端全流程 QA 发现的规格矛盾/空白 needs-decision）

8. **同步轮询间隔上限统一为 1h（裁定：选项 A，替代 D7 的「15s~24h」）**：
   桌面场景轮询上限取 **3600s（1h）**，与 [design/spec.md](design/spec.md) §6.6
   及设置页实现一致；`lk config` 后续补同范围校验（待办）。已修订
   [sync.md](sync.md) §2 与 [cli.md](cli.md) §3（原 D7 其余内容仍然有效）。
9. **审批超时不暴露设置 UI（裁定：选项 A）**：第 3 层弹窗审批超时保持拍板值
   **固定 30s**（默认拒绝语义不变）；守护进程 `config.json` 的
   `approval_timeout_secs` 保留为高级用户调参口（测试可调小），设置页不加项。
   已修订 [design/spec.md](design/spec.md) §6.6（原 D8 其余内容仍然有效）。
10. **自动锁定取值为离散档位（裁定：选项 A）**：空闲自动锁定分钟数取离散档位
   **0 / 1 / 5 / 15 / 30 / 60**（0 = 下次请求即锁，Rust `Config.auto_lock_minutes`
   注释既有语义），与设置页下拉一致；不接受自由数值。已修订
   [ipc.md](ipc.md) §5 与 [design/spec.md](design/spec.md) §6.6
   （原 D10 其余内容仍然有效）。
11. **审计 hmac 不进前端模型（裁定：选项 A）**：防篡改校验是守护进程/CLI 侧
   职责；UI 审计事件流为只读展示、不含 `hmac` 字段，前端 `AuditEvent` 类型
   不建模该字段。已修订 [audit.md](audit.md) §2/§3（原 D11 其余内容仍然有效）。
12. **规则删除语义定案 + #8 待办勾销（2026-08-22 · 来源：文档一致性审查 needs-decision）**：
   (a) **规则删除语义定案**：规则与条目同走「软删 → 墓碑 → 30 天硬删」（即对
       #5「`deleted` 覆盖条目与规则」表述的正式修订依据）；配套实现收尾
       （远端索引重建探测墓碑防复活等）由代码分支落地。
   (b) **#8 待办勾销**：#8 所记「`lk config` 后续补同范围校验（待办）」已完成——
       `SyncConfig::validate` 已按 `MAX_SYNC_INTERVAL_SECS=3600` 收敛为 15..=3600
       并有边界测试（crates/lk-core/src/sync/tests.rs），标记完成。
   已修订 [data-model.md](data-model.md) §6（原 #5 其余内容仍然有效）。
13. **M2 grilling 决议集补登记（2026-08-22 · 来源：文档一致性审查发现「决策 #N」引用不可对位）**：
    M2 grilling（约 2026-08-16）产出的六项拍板当时未登记入本决议集，而全仓
    代码注释与文档已广泛引用「决策 #N」（#1~#6，共 57 处代码引用），本条正式
    补登记使引用可对位，内容如下：
    - **决策 #1 (A)**：`lk inject --keys <name...>` 的密钥名可指名、值不可见，
      值只注入被批准命令的子进程 env（commit 69c4189）。
    - **决策 #2 A**：C 层 daemon 宿主下沉为共享 crate `crates/lk-daemon`
      （`lk_daemon::run(dir)` CLI 入口 / `serve_embedded` 桌面内嵌入口，行为
      不回归；commit 69c4189）。
    - **决策 #3 A**：推送通道 = `transport::PushHub` + `notifier::Notifier`
      （EventSink），订阅连接收 JSON-RPC notification 帧（`subscribe` 方法；
      commit 69c4189）。
    - **决策 #4 A**：桌面窗口/托盘/锁屏（Windows WTS + macOS CGSession）
      生命周期归 Tauri 壳管理（commit 1a61576）。
    - **决策 #5 B**：Windows Hello 置灰预留（V1 不接真生物识别；
      commit 1a61576）。
    - **决策 #6**：规则对象含 `name` 字段（`model::Rule`/`RuleDraft`；
      commit 69c4189）。
    「决策 #10」即补充拍板 #10 的别名；此后新增拍板一律直接进本决议集编号，
    不再使用游离编号。已修订 [AGENTS.md](../AGENTS.md)（对位指引一行）。
14. **跨子系统访问方案定案：interop stdio 桥（2026-08-22 · 来源：WSL CLI ↔
    Windows 桌面守护实例场景设计评审，本机实证后船长确认）**：
    目标 = WSL 内 Linux 原生应用（含 agent）经 `lk` 命令连接同机 Windows
    LightKey 桌面守护实例，查看密钥、请求授权、注入 **Linux 子进程** env；
    全程默认拒绝与三层授权门语义不变。完整规格（含架构、安全分析、实现清单、
    测试计划与本机实证记录）见 [cross-subsystem.md](cross-subsystem.md)，
    本条登记裁定要点：
    - **通道选型**：采用 interop stdio 桥——Linux `lk` 把 JSON-RPC 帧经
      WSL interop 管道交给 `lk.exe bridge` 中继至 named pipe。否决 TCP 监听
      （依赖用户网络环境 + 新增攻击面）、npiperelay 外部工具、Hyper-V Socket
      （未文档化且无法取证）；否决「interop 直调 `lk.exe`」作为目标方案
      （只能注入 Windows 子进程，Linux 工具链拿不到值）。
    - **bridge 默认开关（2026-08-22 船长改定：体验优先）**：平台默认 =
      **auto 探测**——检测到 WSL 即自动探测 bridge（interop + Windows 侧
      daemon.json + lk.exe 安装位置），非 WSL（Linux/macOS 原生）默认本地
      daemon；`LIGHTKEY_BRIDGE=off` 为逃生口、`<路径>` 强制指定中继。
      探测失败**分型处理**：Windows 侧装了但连不上 → 明确报错（绝不静默
      回落本地空库，防「空库错觉」）；Windows 侧未安装 → 静默走本地。
      连接目标始终可见：bridge 命令 stderr 提示 + `lk status` 输出目标字段。
      裁定依据：WSL 本地实例无 GUI → 授权门第③层永远 fail-closed（残缺
      形态），真库与完整授权体验只在 Windows 侧；授权门三层均在守护进程
      侧硬编码，auto 不降低安全下限。
    - **projectDir 跨命名空间归一化**：UNC（`\\wsl.localhost\<distro>\…` /
      `\\wsl$\<distro>\…` / verbatim 前缀）统一归一为 `wsl://<distro>/<rest>`
      规范形；规则入库与运行时 cwd 判定两侧同函数后再做祖先匹配。
    - **协议版本校验**：客户端/bridge 首连校验 `vault.status` 的 `version`
      主.次版本，不一致明确报错拒绝服务、绝不静默降级（来源：实证发现装机
      旧构建对 HEAD 帧静默关闭）。
    - **审计与弹窗**：`channel` 扩展枚举值 `wsl-bridge`；starter 如实展示
      interop 中继链（顶层为 wsl.exe/终端进程），项目目录以 `wsl://` 形态
      展示并标注 (WSL)。
    - **安全基线不变**：bridge 无决策权（安全流程硬编码在守护进程）；无新增
      监听面；用户边界由 interop 同用户令牌 + named pipe ACL 保证；
      启动者取证经实证可行（interop 进程父链 Windows 侧完全可见）。
    - **里程碑归属 M2.75**（M3 浏览器填充之前）；交付含 Linux `lk` 产物 +
      桌面包捆绑 `lk.exe`（当前装机目录缺失独立 CLI，实证发现）。
    老文档回填（ipc.md / authorization-gate.md / cli.md 等）按
    [cross-subsystem.md](cross-subsystem.md) §12 清单在实现时执行。

15. **同用户进程互信边界承认（2026-08-27 · 来源：安全 triage 第二波 #71/#74/#77
    核实，船长拍板）**：`session.token` 文件令牌使**同用户任意进程**在解锁窗口内
    复用解锁态（含 WSL 经 bridge 跨子系统方向），据此被标为 SEC CRITICAL/HIGH。
    核实属实，但该行为是两个既有拍板的直接后果（A1 取舍——CLI 靠文件令牌跨命令
    复用解锁态；补充拍板 #14——WSL 复用桌面解锁态），且与本仓库个人单机工具的
    威胁模型一致：**同用户进程互信为防护边界之外**，与 ssh-agent / `gh auth` /
    aws credentials 等同类凭据存放模型同基线；「有意的同用户攻击者」任何软件
    方案均只能提高成本，不构成边界内威胁模型（Windows 同用户进程可互相注入/
    读取内存）。裁定：
    - `lk unlock` 后同用户进程复用解锁态 = intended behavior，#71/#74/#77 以
      wontfix 关闭（不做会话绑定/token 翻转）；ipc.md §3 / authorization-gate.md
      §7 补边界声明；
    - 若未来威胁模型升级（多 Agent 互不信任成为产品前提），收紧路径 = 按调用方
      区分能力面（#65-A）+ 常驻进程持令牌/连接绑定 token（#68 选项 2）+
      审批一体化（#67）**打包立 spec**，不单独零敲；
    - 本轮不改变 0600/DACL/锁定即删等风险收窄措施（PR #70 已落）。
16. **审批通道信任绑定方案 A+B（2026-08-27 · 来源：安全 triage 第二波
    #72/#78 核实，船长拍板）**：核实属实——`has_ui` 仅看订阅数>0、
    `approval.result` 仅过 require_session，持令牌 socket 进程可「自行订阅 +
    自行回传批准」使第 3 层审批形同虚设。采纳 issue #78 的 A+B 组合：
    - **A 连接标签**：推送订阅登记带来源（桌面内嵌直调 / socket 流连接）；
      `approval.result` 仅接受桌面内嵌直调提交，socket 一律
      `channel.forbidden`（-32014）；`has_ui` 只数 desktop 订阅者；
      `authz.request` 帧（含挑战）只投 desktop 订阅者。
    - **B 一次性 challenge**：`ApprovalChannel::open` 生成高熵随机挑战，
      仅随通知帧下发、回传必须原样带回（错值 → 忽略且条目保留），
      作为连接标签之上的纵深防御。
    - 失败提交写审计（command=`approval.result`）；协议扩展字段
      `approval.result.challenge` 为必填（自端封闭实现，无兼容包袱）。
    实现：crates/lk-core/src/authz.rs / lk-daemon transport::PushHub +
    notifier + daemon/session.rs + dispatch 门；前端 approval 插件透传。

> 约定：如实现中发现新的规格空白或矛盾，在本节登记并上报 needs-decision，不擅改。
