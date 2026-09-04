# Wayfinder 决议集（2026-08-15）

本文档记录 2026-08-15 四轮 grilling 中船长逐条拍板的决议。**本仓库的规格文档
以本决议集为唯一权威来源**；实现时如发现规格与决议矛盾，以决议为准并上报
needs-decision，不得自行变更。

## 背景（已定）

- 路线：**从零自研**——把 Bitwarden 当作“技术规格书”照抄设计（抄设计不抄代码，
  不 fork、不用 Bitwarden/Vaultwarden 当底座）。
- 许可：**客户端全开源（MIT）**；服务端（如未来有）不开源；付费暂缓。
- 本仓库：`jibuji/lightkey`（private）；本地 no-mistakes 闸门已于 2026-08-29
  移除（补充拍板 #21），质量门禁由 PR 触发的 GitHub CI 承担。

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
      区分能力面（#65-B）+ 常驻进程持令牌/连接绑定 token（#68 选项 2）+
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

17. **`lk inject` secret 值内存生命周期加固：策略 B+C（2026-08-27 · 来源：
    issue #76（SEC HIGH）核实，船长拍板）**：核实属实——`lk inject` 的值经
    daemon `authz.evaluate` 响应 → CLI 物化 `decision.env`（`BTreeMap<String,
    String>` 明文）→ `child.envs(&env)`，secret 值在 lk CLI 进程内存明文持有，
    暴露给 core dump（`ulimit -c`）/WER/ptrace。采纳 **B（保守加固，backward
    compatible）+ C（文档/承诺如实降级）** 组合；执行计划路由/授权门语义零变更，
    不动 daemon 侧 authz/approval/审计归因。
    - **B CLI 侧加固（不改 IPC 与 daemon 行为）**：
      - `decision.env` 值在 `child.envs(&env)` 之后**立即 zeroize**（`zeroize`
        crate 对 `String` 的内建实现，原地擦除堆缓冲；`memguard::zeroize_env`）；
      - Linux：CLI 启动即 `prctl(PR_SET_DUMPABLE, 0)`（经 libc），禁 core dump
        落下明文，且限制非相关进程直接 ptrace；进程级一次性设置，放 main 早期；
      - Windows：`SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)`
        尽力抑制 WER 错误框（不做过度工程；Windows 分支补 cfg 编译 + 单元测试，
        验收以 Linux 为主）。
    - **威胁模型边界如实声明**：**不防同用户调试器**——ptrace/inject 读取
      进程内存仍由同用户身份可完成，同用户进程互信已在补充拍板 #15 划在
      防护边界外；本项加固只缩短明文存续、降低 core dump/WER 落下磁盘的成功面。
    - **C 文档/承诺如实降级**：`docs/cli.md` inject 节、`cmd_inject` 注释、
      `lk inject --help` 同步表达「值会经 lk CLI 进程内存传递一次（已做
      zeroize + 防 dump 加固），仅排除 stdout/日志/审计；不防同用户调试器」。
    实现：crates/lk-cli/src/memguard.rs（`harden_process` / `zeroize_env` /
    测试）+ crates/lk-cli/src/main.rs（`main()` 启动加固、`cmd_inject` 注入后
    zeroize、--help 文案）+ 文档。
18. **审计文件外锚点（截断可证明）（2026-08-27 · 来源：issue #75（SEC MEDIUM）
    核实 + 实现，船长拍板）**：核实属实——审计链是逐事件 HMAC-SHA256 链，但
    文件系统层面只是 0600 追加式文件，**无文件外可信锚点**：同用户攻击者可截尾
    尾部抹掉近期事件、或删文件让守护进程重建空链，截断后的链仍能通过
    `audit.verify`（验证器只走首尾 HMAC，「篡改可检测」≠「篡改可证明」）。裁定
    设计取向为**「截断可证明」，而非「截断可预防」**（同用户总能写数据目录）：
    - 锚点值 = 链尾 `{ordinal, last_hmac}`（最后一条事件 HMAC + 序号）；
    - 写入点：解锁/锁定/恢复（密钥轮换）/守护进程干净关闭低频同步写 + 后台
      60s 异步 flush（**热路径非阻塞**，不得持 vault 写锁——G1 纪律）；
    - 平台存储：Windows Credential Manager / macOS Keychain / Linux
      secret-service·keyutils（经 keyring crate；失败统一映射 Unavailable，
      无 panic）；平台不可用 → **fail-open** 降级到数据目录 0600 原子写侧写
      `audit.anchor` 并告警，**绝不阻断 vault 解锁**；降级 ≠ 可信，文档明示更弱；
    - `lk audit --verify` 交叉核对锚点：截尾 / 锚点缺失 / 锚定事件被替换 →
      报「truncation detected」语义错误且 CLI **退出非零**；链长于锚点的
      「锚点后追加」不误报；
    - `vault.status` 暴露可选 `auditAnchorOk`（`false` 覆盖「降级/截断/缺失」
      三态，桌面 UI 告警通道；前端类型向后兼容可选字段）；
    - 锚点值无需 K_audit（只读链尾）→ 锁定态也可写锚点；
    - 同用户边界衔接补充拍板 #15：截断可证明 ≠ 可预防，不做防同用户删除的
      虚假承诺。
    实现：crates/lk-core/src/audit_anchor.rs + crates/lk-daemon/src/audit_anchor.rs
    （KeyringAuditAnchor + Composite + FileAnchorSidecar）+ daemon（sync_anchor /
    flusher / 启动自检 / vault.status.auditAnchorOk）+ lk-cli（audit --verify
    截断检测）+ 前端（auditAnchorOk 可选字段）+ docs/audit.md §3.2。

19. **锁定态 inject 一体化：临时解锁 + 本次授权为一次交互（2026-08-27 · 来源：
    issue #67（UX 断层）与 #65（inject 后顺手获得全量令牌）再核实，船长拍板）**：
    此前按补充拍板 #15 约定「#65-B 能力面 + #67 审批一体化 + #68-opt2 常驻令牌
    打包立 spec、暂缓」，本次指令提前实现其不冲突部分：
    - **#67 全量**：库处于锁定态时收到 `authz.evaluate`（即 `lk inject`），若桌面
      审批界面在场（desktop 推送订阅存在），把「临时身份确认（解锁）+ 本次行为
      授权」折叠成 GUI 上的一次交互——弹窗同时展示主密码输入栏（身份确认）与
      启动者/项目目录/命令/key 名/倒计时（行为授权），用户一次性完成临时解锁 +
      本次授权；**GUI 不在运行（纯 headless）维持 fail-closed `session.invalid`**
      （CLI 仍提示先解锁，不阻塞、不静默回落）。
    - **#65 配套（关键约束）**：一体化流程**不签发会话令牌 / 不写 session.token /
      不置 shared.vault**——vault 保持锁定，仅做临时解锁内存态供本次注入 + 审计
      签名，解锁材料只服务本次注入，**不产生 item.* 全量读能力**（#65 的主要
      担忧由此闭环）。
    - 协议/前端配套：`ApprovalResultParams.masterPassword`（可选，仅 needs_unlock
      待审 + allowed 决策使用并校验）；`ApprovalRequest.needs_unlock` 与
      `authz.request` 帧 `needsUnlock` 字段；desktop 来源 `subscribe` 允许**锁定态**
      订阅（推送目标注册，桌面直调无需会话；帧无密钥值，socket 订阅照旧要求会话）。
    - 审计两条：`vault.unlock`（channel=desktop，via=inject-gui）+ `lk inject`
      （channel=approval），均用**临时 vault 的 K_audit** 签名；拒绝/超时且未解锁
      （无临时 vault）→ 无 K_audit 不可签名，**不写审计**（与 v0 锁态拒绝同口径，
      fail-closed 不留审计内容）。
    - **#65 其余（item.* 能力面按调用方区分 / 常驻进程持令牌，#15 的方向 B）仍按
      补充拍板 #15 推迟**：威胁模型不变（同用户进程互信在防护边界之外），仅在
      威胁模型升级（多 Agent 互不信任成为产品前提）时打包立 spec。#65 文档边界
      声明（authorization-gate.md §7）维持，不因本次一体化撤销。
    实现：crates/lk-core/src/{ipc,authz,bus}.rs + crates/lk-daemon/src/{daemon/
    {authz,mod,session}.rs, notifier.rs, router.rs} + 前端 {events,ipc/*,plugins/
    approval.tsx} + E2E/单测。

20. **安全边界修订：产品接口面即边界，#65-B 立项（2026-08-28 · 来源：issue #65
    复议，船长拍板）**：修订补充拍板 #15 的后半句——「同用户进程互信为防护
    边界之外」不再覆盖**经产品接口到达的请求**（IPC socket / named pipe /
    桌面内嵌直调 / CLI / 未来 Native Messaging）。#15 前半句维持：同用户
    **原生攻击者**（调试器、内存注入、键盘钩子等**绕过产品接口**的路径）仍在
    边界外，如实声明（#17/#18 处置不变）。修订依据：被提示注入操纵的 agent
    仍是走合法 API 的同用户进程，接口层能力收敛对它真实有效——这正是 D8 的
    立项目标；ssh-agent 类比对 LightKey 不成立，因为 LightKey 自己承诺了
    「agent 只能看到被授权的 key 名」，承诺与边界必须一致。裁定：
    - **令牌 = 认证，不 = 授权**：会话令牌只证明「存在已解锁会话」；**值的
      披露必须是一个授权事件**——用户预写的规则命中，或用户当场的弹窗批准。
      桌面内嵌直调通道（人在 GUI 前）默认受信（复用 #78 连接标签）。
    - **item.get / item.export 升为裁决方法**（复用 #81 的 ApprovalDeferred
      编排，`router.rs strategy_of` 登记扩展）：读走三层——读规则（新增规则
      能力类型：projectDir + keys，无 command 绑定）→ 桌面弹窗（30s 超时
      拒绝）→ fail-closed 拒绝；**export 恒弹窗，任何规则不豁免**（整条目
      数据包含附件原始数据、单次披露量最大）。git hook / cron /
      VSCode task / WSL bridge 等
      合法程序化读由读规则覆盖（WSL 侧复用 starter 链回溯 + `wsl://` cwd
      归一化，无新机制）。
    - **元数据维持令牌门**：`item.list`（名称）与 `rule.list`（规则内 key 名）
      照旧持令牌即可读——值是边界，名称如实降级。D8「未授权 key 名不可见」
      的承诺修订为「**在 inject 通道内严格成立；持令牌进程可见条目/规则
      元数据**」（authorization-gate.md §2 同步修订）。
    - **不依赖「交互式 / 程序化可区分」的启发式**（脚本与手敲的进程链同形、
      TTY 可被继承可被伪造）：人在场的证明交给弹窗本身。弹窗提供「允许并为
      此项目记住（存为读规则）」一键（GUI 写规则本就是 D8 合法路径），把
      重复交互降为一次。
    - **#68 选项 2（常驻进程持令牌）降级为观望**：dispatch 层能力门已把被盗
      令牌的残值压到「元数据 + 规则范围内」；#68-opt2 关闭的是令牌获取路径，
      但要重构 A1（文件令牌跨命令复用），代价高、边际收益小。仅在元数据
      泄露被用户认为不可接受时再议，不与本项捆绑。
    - **交付纪律**：上述落成一个完整 spec（authorization-gate.md §2/§7/§8 +
      ipc.md §3 + data-model.md 读规则 schema），实现按 TDD 在
      `router.rs strategy_of` / dispatch seam 先立失败测试；**#65 保持 open
      至 spec 落地再关闭**。

21. **PR 恢复自动 CI + 本地 no-mistakes 闸门移除（2026-08-29 · 船长拍板）**：
    - **CI 触发面恢复 pull_request（opened / synchronize / reopened）**：提交 PR
      或 PR 更新即自动运行 `.github/workflows/release.yml` 同一套构建前置门禁
      （Windows：fmt/clippy/test 三 crate + 前端 npm test；Linux：lk-cli
      clippy/test）。PR 运行属非发布路径：check-version 跳过、不发布 Release、
      不传 artifact（省私有仓库存储配额）；并发组按 event+ref 隔离，PR 更新
      自动取消上一轮未完运行。2026-08-27「CI 只在 release 时运行」裁定自此
      修订为「release + PR 双触发，非 PR 的提交仍不触发」。
    - **本地 no-mistakes 闸门移除**：`no-mistakes eject`（gate remote、裸仓库、
      worktree、DB 记录一并清除）+ 残留清理（`refs/no-mistakes/sync/*` 与 Temp
      基线 worktree）。交付纪律改为**功能分支 + PR + GitHub CI 门禁**，不再经
      `/no-mistakes` 管道验证。
    落盘：`.github/workflows/release.yml`、AGENTS.md（「常用命令」CI 条目 +
    「交付纪律」）、本条。

22. **规则管理审批门 + E2E 自动批准通道（2026-08-31 · 来源：issue #102/#104
    agent 集成 grilling 收敛稿，船长拍板）**：socket/pipe 通道的 `rule.add` /
    `rule.remove` 从「仅验会话令牌」升为**桌面审批门**——对称原则：授权的
    建立（agent 给自己 `rule add --read` 持久授权 = 自我提权）与撤销
    （`rule remove` 删用户既有规则 = 拆墙）都是授权事件（补充拍板 #20 的
    自然延伸）。裁定：
    - **范围**：socket/pipe 的 `rule.add` / `rule.remove` 走 ApprovalDeferred
      三阶段（ADR-0001 编排复用）；GUI desktop 直调受信豁免（设置页、读值
      弹窗「允许并为此项目记住」内部的 ruleAdd——人在 GUI 前零摩擦）；bridge
      通道对端非 desktop 自然受门；`rule.list` 维持令牌门（只读元数据，
      M2.9「值是边界，名称如实降级」同口径）；锁态 `session.invalid` 先行
      （规则在加密库内；锁态规则管理一体化在规格 Out of Scope——规则是参与
      同步的持久对象，管理低频，先解锁再管理）。
    - **协议加性变更，不升版本**：`ApprovalKind` 新增 `Rule`（serde 小写
      `"rule"`）；**单一 kind + command 字段承载操作**（`rule.add <name>` /
      `rule.remove <name>`，不拆两个 kind）；remove 由 daemon 解析 id→规则
      补全 name/keys/projectDir 供弹窗展示。错误码**复用 -32017
      `authz.denied`**（协议零新增；既有 -32014 撞码是「新增码会漂移」的
      实证）；CLI 按命令上下文渲染「规则变更被授权门拒绝…」（同码不同命令
      语境区分，机器契约 error 名不变）。
    - **finalize 锁内重校验（TOCTOU）**：30s 等待窗内规则库可能被并发审批
      落盘或同步轮次改变；finalize 必须在锁内重验 vault 解锁态与（remove 的）
      规则存在性（按**未删除**口径——`get_rule` 含墓碑、幂等 delete 会静默
      成功，不能用作重验），失效则拒绝并落审计，不产生基于过期快照的写入。
    - **审计全路径**（现状仅成功路径写）：批准 → channel=approval + Allowed；
      拒绝/超时/无 UI → Denied/Timeout（socket 归因如实，wsl-bridge 照旧）。
    - **前端**：approval 插件 kind=rule 分支（命令框 + keys Tag + 30s 倒计时，
      无「记住」按钮——规则操作本身就是持久动作）+ **未知 kind 防御性渲染**
      （明确提示而非回退按 inject 渲染，协议演进时旧 UI 不误导）；D 层单测
      钉住。
    - **E2E AutoApproveChannel**：`ApprovalChannel` trait 新增 env 门控装饰器
      ——daemon **启动时**读一次 `LIGHTKEY_E2E_AUTO_APPROVE=rule`，仅对
      `ApprovalKind::Rule` 立即 Allowed（不碰 inject/披露审批，
      `available()` 语义原样透传，headless inject 照旧立即拒绝）；审计
      channel=auto-approve（command 含 requestId 与规则内容）+ daemon 启动
      日志横幅——**测试通道绝不静默**。
    - **release 二进制保留 auto-approve 路径是有意决策**：E2E 必须测发布物
      本体；编译期 feature/cfg 门为被否选项（会测非发布物、削弱 E2E 价值）。
      攻击面结论：env 仅在 daemon 启动时读取，攻击者自带该变量拉起的新
      daemon 库是锁的、`rule.add` 仍过会话门（`session.invalid`），无权限增益。
    - **集成形态钉死为「skill 包装 `lk` CLI」，MCP server 作为被否替代留档**：
      daemon 归因依赖 IPC 对端 PID 进程链回溯与 cwd 绑定；MCP 常驻 server 会
      把归因目标变成 server 自身，若让 server 转发客户端自报身份则违反
      「不信客户端自报」第一原则，且新增一整块协议面。未来可复议。
    - 被否选项：
      | 选项 | 否因 |
      |------|------|
      | MCP server 集成 | 归因失真（server 自身）或违反「不信客户端自报」；新增协议面；本条留档可复议 |
      | 编译期 feature/cfg 门 auto-approve | E2E 会测非发布物、削弱 E2E 价值；env 门 + 审计标注 + 启动横幅已足够可见 |
      | 拆 `ApprovalKind::RuleAdd` / `RuleRemove` 两个 kind | 协议面翻倍；单一 kind + command 字段已可承载操作与弹窗渲染 |
      | 新错误码区分规则门拒绝 | 应用段错误码已现撞码实证（-32014 双义）；复用 -32017 + CLI 语境文案零协议变更 |
      | 锁态规则管理一体化解锁 | 规则是参与同步的持久对象（revision/CAS/墓碑），管理低频；先解锁再管理 |
      | 规则门走读规则豁免（如「已有同名规则不弹窗」） | 规则变更本身就是授权事件，任何豁免都重开自我提权面 |
    - 测试分工：shell E2E（env 门生效主流程 + 「无 env 时 headless rule add
      被拒」）；daemon 集成测试进程内驱动 `LocalApprovalChannel`（模拟桌面
      订阅 + `approval.result` 直调）覆盖人工批准/deny/超时/no_ui/remove 门/
      锁态/TOCTOU 竞争/auto 通道。
    实现：`crates/lk-core/src/{authz,audit}.rs` +
    `crates/lk-daemon/src/{router.rs,daemon/{mod,rules}.rs}` +
    `crates/lk-cli/src/main.rs` + 前端 `{events.ts,ipc/mockAdapter.ts,types.ts,
    plugins/{approval,ui-audit}.tsx}` + `scripts/e2e_{m0,m1,m2,cross_subsystem}.sh`；
    规格：authorization-gate.md §9。

23. **读通道一体化解锁：锁态 `item.get` / `item.export` 弹「主密码 + 解锁
    并允许」窗（2026-08-31 · 来源：issue #105（#102 epic PR3 / 补充拍板 #23），
    船长拍板）**：锁定态 + 桌面 UI 在场时，值披露的断点体验（#102 问题 3）
    收口——与 #67 注入一体化同款机制，**协议零新增**（`needsUnlock` /
    `masterPassword` / `kind` 三要素已就位）。裁定：
    - **范围**：`item.get` 与 `item.export` **两者都做**（机制相同——单条目
      单次披露、临时 vault 即用即毁；只做 get 会留 export 断点不一致）。
    - **锁态必弹窗**：即使该条目已有 read 规则命中也必弹——规则在加密库内
      无法预载（与 #67 inject 同款妥协），文档明示「锁态下一切披露都要一次
      交互」。未初始化库（initialized=false）：不弹解锁窗，维持 fail-closed；
      无 UI：维持 `session.invalid`；解锁态行为零变化。
    - **临时 vault 生命周期**（延续 #65 边界）：不签发会话令牌、不写
      `session.token`、不置共享 vault，单次披露执行即毁；密码错误 →
      `vault.invalid` 统一文案防探测、弹窗内可重试（AuthGuard 限流照常）；
      等待期间整库被解锁 → finalize 走**常态路径**（共享 vault）；等待期间
      被锁定 → `session.invalid`（与 inject 同口径）。
    - **daemon 侧**：披露预检分流（未初始化 / headless 维持 fail-closed；
      initialized && 锁态 && 有 UI → 登记 `Pending{needs_unlock:true}`）；
      finalize 复用 #67 的 `approval_result_unlock` 临时 vault 编排，在临时
      vault 上执行披露（get/export exec 支持传入 vault 引用）+ 审计
      （channel=approval，用临时 vault 的 K_audit 签名）。
    - **前端「记住」按钮渲染条件改为 `isRead && !needsUnlock`**：现状只按
      isRead，锁态 read 弹窗会渲染「允许并为此项目记住」但 remember 被静默
      丢弃（needsUnlock 分支不传 remember）——误导性 UI；这是**真实代码变更**
      而非「保持现状」，以 D 层单测钉住「锁态 read 弹窗无记住按钮」。
    - **已知限制（留档，不阻塞本规格）**：锁态下 agent 循环重试可致弹窗轰炸
      ——每个 pending 走 30s 超时默认拒绝，恶意/失控 agent 可高频刷弹窗。
      后续可选加固：同 (starter, 条目) 合并去重 + 每 starter 并发上限/限流
      （notes 于 [authorization-gate.md](../docs/authorization-gate.md)
      §5.2 与 [value-disclosure.md](../docs/value-disclosure.md) §12）。
    - 被否选项：
      | 选项 | 否因 |
      |------|------|
      | 只做 `item.get` 一体化 | export 断点不一致；两者机制相同，不做就是半成品 |
      | 锁态 read 规则直接放行（不弹窗） | 规则在加密库内无法预载；放行将打开「锁态可自动披露」的安全洞，与三层授权门语义冲突 |
      | 记住按钮在 needsUnlock 时「降级为仅本次」 | 语义含糊；直接不渲染更诚实（`isRead && !needsUnlock`），避免 UI 承诺做不到的持久授权 |
      | 锁态弹窗合并去重/限流随本规格交付 | 属可用性加固，收益确定性弱、协议/架构面新增；记为已知限制后续可选 |
    实现：`crates/lk-daemon/src/{router.rs,daemon/{disclosure,items,session,mod}.rs}`
    + 前端 `{plugins/approval.tsx,__tests__/m2.test.tsx}` +
    `crates/lk-daemon/src/tests/disclosure.rs`；规格：
    value-disclosure.md（判定矩阵锁态行）、authorization-gate.md §5.2。

24. **写入授权门（write gate）：写 = 授权事件（2026-09-02 · 来源：
    write-gate grilling-with-docs 会话收敛，船长拍板，**已实现**——M2.97
    PR A-D 序列经 PR CI 门禁落地，issues #112-#115）**：
    `item.put` / `item.delete` 从「仅验会话令牌」升为裁决方法——值披露是
    授权事件（#20），**写入同样是授权事件**（对称原则完成面）：解锁窗口内
    任何同用户进程持令牌即可静默新建/整条替换/删除任意条目，与 #65 同源
    （value-disclosure §1 的镜像）。裁定：
    - **结构**：`Rule.capability` 增 `write`（三能力 inject/read/write 两两
      不互授）；写规则带 `actions ⊆ {create, update, delete}`，缺省
      create+update；**delete 恒弹窗由协议保证**——不存在于 actions，规则
      写不进去。
    - **协议零变更，RPC 不拆**：单一 `item.put`（action 由 daemon 从
      `ItemPutParams.id` 有无权威派生，不信客户端自报）+ `item.delete`；
      `ApprovalKind::Write`（serde `"write"`）加性新增；拒绝复用
      `-32017 authz.denied`（协议零新增）。拆分 `item.create/update` 为被否
      选项（破坏性协议变更 + 三处契约镜像 + 表面翻倍）；清晰度由 daemon
      内部函数拆分获得。
    - **判定矩阵**：desktop 直调受信豁免；socket 写规则命中静默
      （**双向名称约束**：create 草稿名 ∈ keys；update 存储名 **且** 草稿名
      都 ∈ keys——名字不得「进出」授权集合，堵「改名逃生 / 改名植毒」）；
      未命中 → 弹窗（30s 超时默认拒绝）/ headless `authz.denied`；
      **delete 恒弹窗任何规则不豁免**（无用户级恢复路径——软删 30 天后
      硬删、无 restore 命令；对齐 export 恒弹窗先例）；重名语义 = 名字即
      身份（规则覆盖全部同名条目，与读规则同构）；锁态 `session.invalid`
      先行（规则在加密库内）。
    - **边界**：同步应用远端变更不受门（BYO 信任模型维持，与值披露同口径）；
      真相源投毒（写规则静默改写 secret 值 → 后续合法读/注入拿污染值）接受
      为已知限制（文档明示，delete 恒弹窗已压住最坏损失）。
    - **测试**：E2E **不扩展** auto-approve 到写门（shell E2E 覆盖 headless
      拒绝 / 写规则命中静默 / delete 恒弹窗拒绝，预插经既有
      `auto-approve=rule`；弹窗批准路径由 daemon 集成测试
      `LocalApprovalChannel` 覆盖——与值披露门测试分工一致）。
    - 留档（后续可选，不进 MVP）：锁态写一体化（#67/#23 同款）；secret
      类型 update 恒弹窗（规则级 flag）；写规则 id 键（对象级钉死，create
      另案）；弹窗合并去重/并发上限（沿用 #23 留档）;规则绑定 exe+哈希
      （进程身份绑定，整体可选加固）。
    - 被否选项：
      | 选项 | 否因 |
      |------|------|
      | 拆 `item.create` / `item.update` RPC | 破坏性协议变更（旧 daemon 不兼容、需升桥版本或留废弃别名）+ 三处契约镜像同步改 + 表面翻倍；daemon 内部函数拆分即可获得同等清晰度 |
      | delete 可由写规则豁免 | 无用户级恢复路径（软删 30 天硬删、无 restore）；任何豁免重开「静默拆墙」面（对称 export 恒弹窗） |
      | 写规则按条目 id 键匹配 | 规则不可读（UUID 配置表）、create 无 id 需另案、keys 一处两种语义；「名字即身份」符合用户直觉且与读规则同构 |
      | E2E auto-approve 扩到写门 | release 二进制自动批准面扩大；headless 拒绝/规则静默/恒弹窗已被既有通道覆盖 |
      | 锁态写一体化随 MVP 交付 | 写比读更重；规则在加密库内锁态无法预载；现维持 `session.invalid`，机制复用 #67/#23 后续可选 |
    实现规格：[write-gate.md](write-gate.md)（**唯一出处**）；落点：
    authorization-gate.md §10（摘要）、ipc.md / cli.md / agent-cli.md /
    data-model.md（标注）、milestones.md M2.97、CONTEXT.md（写入/写动作/
    写规则/恒弹窗词条）；**已立项并按 PR 序列落地**（epic #111，issues
    #112-#115，实现走 PR CI 门禁序列，write-gate.md §11）。

25. **规则程序指纹绑定（identity binding）：授权目标是程序而非命令形态
    （2026-09-02 · 来源：identity-binding grilling-with-docs 会话收敛，船长
    拍板，**已实现**）**：规则（inject/read/write）授权的是「项目目录 +
    命令形态 / 条目名」，**不含"哪个可执行文件"维度**——任何同用户进程在
    授权目录内**复现授权命令形态**即可命中（PATH 前置同名假程序截获注入
    env、目录内任意进程按写规则条目名静默覆盖等）。基线事实：规则里不存在
    身份可供"伪造"，攻击者是复现形态。裁定：
    - **结构**：`Rule.fingerprint: Option<ProgramFingerprint>`（serde
      default = `None`，旧规则零迁移、密文反序列化不受影响；未绑定 = 现状
      语义，如实降级）；`ProgramFingerprint { exe_path, sha256, size }`
      （canonical 路径 + SHA-256 + 固化时大小）。
    - **绑定对象**：注入规则绑定**被注入命令的可执行文件**（`command[0]`）
      ——本项主线，闭合"命令形态冒充"；读/写规则**可选**绑定调用方链（仅
      显式启用、限独立工具二进制场景——终端/IDE/脚本的 starter 不稳定，
      升级即失配，文档明示局限）。
    - **失配 = 未命中**：**不新增错误码**（防探测——不给"规则存在但指纹
      不符"的枚举信号）；GUI 弹窗明示「程序指纹与规则不符（可能已更新）」
      +「**以新指纹重新授权**」（复用规则管理审批门，daemon finalize 侧
      重算指纹落盘）；headless 统一 `authz.denied`。
    - **解析认证在 daemon 侧**（信 daemon 不信客户端，与 starter/cwd 同
      原则）：对端**真实 env** 的 PATH——Linux `/proc/<pid>/environ`、
      Windows PEB `ProcessParameters.Environment`（复用 starter.rs 基建）、
      macOS `KERN_PROCARGS2`（实现期验证，失败 fail-closed）；比对序 =
      路径 → size → SHA-256（前两关免哈希快速失配）。
    - **大文件性能**：**内存指纹缓存 + 元信息失效**（先 stat，size/mtime/
      inode 一致即复用缓存哈希，成本 = O(stat) 与文件大小无关）；缓存**不
      落盘**（落盘缓存可被同用户进程投毒成"自己二进制"的哈希——正是要防
      的冒充）；阈值 **64 MiB**（默认，可配置）只决定预计算时机，不改安全
      语义；SHA-256 全量读一次是底线成本，方案只降频率不降单次。
    - **威胁边界**：防「**冒充**」——PATH 前置假程序 / 同名假程序 / 复现
      命令形态；攻击者能**就地改写授权二进制本身**（含恢复 mtime/内容）＝
      她就是这个程序，指纹无能为力——与同用户原生攻击同属 #15/#20 边界外
      （文档明示）；校验与 spawn 之间换文件竞态同理接受 + 声明，不做
      "daemon 返回指纹由 CLI 复核"的伪强加固（CLI 不可信，复核无意义）。
    - 被否选项：
      | 选项 | 否因 |
      |------|------|
      | 代码签名验证（Authenticode/notary） | 跨平台无统一方案；升级换代/供应链复杂度高 |
      | 失配新增专用错误码 | 泄漏"规则存在但指纹不符"的枚举信号，反助攻击者；与"未命中"同路径即可 |
      | 指纹缓存落盘 | 同用户进程可投毒缓存放行自己的二进制——正是防冒充的反向；内存缓存足够 |
      | daemon 下发指纹由 CLI spawn 前复核 | CLI 是同用户不可信方，复核无意义；换文件竞态已归入边界外 |
    - 留档（后续可选，不进 MVP）：代码签名验证；阈值数值可配置；macOS
      env 读取实现期验证（不可行则该平台指纹规则 fail-closed）。
    实现规格：[identity-binding.md](identity-binding.md)（**唯一出处**）；落点：
    authorization-gate.md §11（摘要）、data-model.md（标注）、milestones.md
    M2.98、CONTEXT.md（程序指纹词条）；**已立项并按 PR 序列落地**（父立项
    #121，issues #123-#126，实现走 PR CI 门禁序列，identity-binding.md §11）。
    **read/write 调用方链绑定按 spec §12 默认仅字段预留**（适用边界=独立
    工具二进制场景，文档明示），不落地 CLI/UI。

26. **Linux memguard 机制修订：`RLIMIT_CORE=0` 替代 `PR_SET_DUMPABLE=0`
    （2026-09-04 · 来源：issue #119（#76 加固与 #66 归因互斥——M2.97 T3 发现，
    PR #118 探针实证 `readlink /proc/<pid>/cwd` EACCES），船长拍板）**：
    修订决策 #17 的 Linux 子句——`lk` CLI 启动加固改为
    `setrlimit(RLIMIT_CORE, {0,0})`，**不再** `prctl(PR_SET_DUMPABLE, 0)`。
    - **根因（探针实证，WSL2 Debian 6.18 内核 fork 探针）**：非 dumpable 进程
      的 `/proc/<pid>/{cwd,environ,exe}` 对同用户守护进程走 `ptrace_may_access`
      门返回 EACCES（同进程自读不受门，须跨进程复现）；`comm/stat/cmdline`
      仍可读。结果 `starter::resolve_peer_cwd`（#66）取不到对端 cwd →
      授权门第 1 层 fail-closed → **Linux 上 inject / 读 / 写全部拒绝**
      （`e2e_m1.sh` 阻塞）；同一机制还阻断 M2.98 指纹绑定的对端
      `environ` PATH 读取（#121 Linux 面，identity-binding.md §5.1）。
    - **裁定方向 2**（issue 候选 2）：换不影响 `/proc` 可见性的机制。
      `RLIMIT_CORE=0` 完整保留 #76 核心承诺（core dump 不落下明文），且
      rlimit 可被 fork/exec 继承——注入命令**子树**同样禁 core，覆盖比原实现
      更广（原 `PR_SET_DUMPABLE` 在子进程 exec 时复位，只护 CLI 自身）。
    - **被放弃的副产品重评**：「限制非相关进程直接 ptrace」。(a) #15/#17 已
      声明同用户调试器在防护边界外，该限制属边界内的额外摩擦；(b)
      Debian/Ubuntu 默认 `kernel.yama.ptrace_scope=1` 已限制非父子进程
      ptrace，收益与系统默认重叠；(c) Linux 无「禁 core 但保留 /proc」的
      独立开关——不放弃则归因无解。
    - **被否选项**（issue 候选 1/3）：对端主动上报 + 校验（需协议面新字段，
      违背 D8「不信客户端自报」第一原则；且只修 cwd 不修 environ）；netlink/
      audit（需特权/内核特性，cwd 无现成事件源）；Linux 上声明 memguard 与
      授权门互斥（E2E SKIP）——与 M2.98/M3 Linux 推进方向冲突，`e2e_m1.sh`
      永久不能跑绿。
    - **实现**：`crates/lk-cli/src/memguard.rs`（Linux 分支 setrlimit +
      模块文档修订）+ Linux 回归测试（fork 子进程 `harden_process()` 挂起 →
      父进程断言 `lk_core::starter::resolve_peer_cwd` 与对端
      `lk_daemon::identity::PlatformPeerEnv::peer_path` 仍可读 + 子进程自检
      `PR_GET_DUMPABLE`=1 / `RLIMIT_CORE`=0 经退出码回传）+ `docs/cli.md`
      引用更新。**Windows/macOS 路径零改动**；fail-closed 语义不变（归因
      真实不可得仍拒绝）。
    - **验收**：Linux headless 规则命中 `lk inject` / `item.get` / `item.put`
      放行；`scripts/e2e_m1.sh` / `e2e_m2.sh`（Linux）恢复跑绿。

> 约定：如实现中发现新的规格空白或矛盾，在本节登记并上报 needs-decision，不擅改。
