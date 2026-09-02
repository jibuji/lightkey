# AGENTS.md — LightKey 项目知识

面向几乎每个未来会话的项目级知识；细节一律指向权威文件，不在此复制。

## 项目一句话

轻钥 LightKey：个人密钥/私密信息管理工具，从零自研（不 fork Bitwarden），
客户端全开源（MIT）。当前为 **M2 完成（授权门 + 桌面端）** 阶段。

## 规格是唯一权威

- 所有设计决策见 [`docs/decisions.md`](docs/decisions.md)（2026-08-15 拍板，
  勿自行变更；发现矛盾走 needs-decision 上报）。历史「决策 #N」编号
  （M2 grilling 集）见 decisions.md 补充拍板 #13 映射。
- 文档地图：[`docs/README.md`](docs/README.md)；里程碑：[`docs/milestones.md`](docs/milestones.md)。
- 文档语言为中文；标识符/命令/协议字段用英文。

## 常用命令

- 核心+daemon+CLI 测试/检查（Linux 上 Tauri 壳需 webkit2gtk，CI 在 Windows 检查；
  Windows 优先，补充拍板 #4）：
  `cargo test` / `cargo fmt --all -- --check` / `cargo clippy --all-targets -- -D warnings`
  （三 crate：lk-core / lk-daemon / lk-cli）
- 同步 E2E（M1 双客户端）：`bash scripts/e2e_m1.sh [lk-binary-path]`；
  单机回归：`bash scripts/e2e_m0.sh`；授权门 E2E（M2）：`bash scripts/e2e_m2.sh`
  （都用 `file://` 本地模拟存储，无需凭据）；跨子系统 E2E（M2.75，
  WSL2+Windows 桌面包前置不满足则 SKIP exit 0）：
  `bash scripts/e2e_cross_subsystem.sh [lk-binary-path] [--auto-approve]`。
- 前端：`cd frontend && npm install && npm run build`（Vite 端口 1420 与
  `crates/lk-app/tauri.conf.json` 的 devUrl 一致）；D 层单测 `npm test`
  （vitest；事件总线契约/装配/宿主渲染/审批弹窗/条目域纯函数）。
- 桌面壳 Windows 验收：`cargo check --workspace --target x86_64-pc-windows-gnu`
  （本地需 mingw 交叉工具链：conda env `lightkey-mingw`，PATH 前置其 bin；
  Linux 无 webkit2gtk 不编译 lk-app）。
- CI 触发面 = pull_request（opened/synchronize/reopened，2026-08-29 裁定：
  提交 PR 或 PR 更新自动跑门禁；PR 运行不传 artifact、不发布）+ tag `v*`
  push / workflow_dispatch（2026-08-27 裁定：非 PR 的提交不触发）。
  唯一 workflow 为 `.github/workflows/release.yml`（原 `ci.yml` 已删除），
  全部质量检查（Windows：
  fmt/clippy/test 三 crate + 前端 npm test；Linux：lk-cli clippy/test）
  作为**构建前置门禁**内嵌在 build job 里
  （`crates/lk-app/tauri.conf.json` bundle.active=true，NSIS+MSI；独立 CLI
  Windows `lk.exe` + Linux `lk` 双产物；tag `v*` → GitHub Release 附件（两个 build
  job 均需 `permissions: contents: write`）；不带 release_tag 的 dispatch →
  Actions artifact，dispatch 传 `release_tag` 输入可把产物补发到既有 Release
  （不移动标签）；发布路径（tag / 带 release_tag 的 dispatch）先过 check-version
  闸门：去 v 前缀的发布 tag 须等于根 Cargo.toml [workspace.package] version
  （lk-cli 经 workspace 继承），不一致 fail（#34）；bump 版本属发版动作，勿顺手改；
  资产名版本号 tag/dispatch 触发时取对应 ref 去 v 前缀，否则回退
  tauri.conf.json；产物未签名属预期）。
  注意：桌面包经 bundle.resources 捆绑 `target/release/lk.exe` 进安装目录——
  手动打版必须先 `cargo build --release -p lk-cli` 再 `cargo tauri build`
  （顺序颠倒 bundler 会因资源缺失响亮报错）。

## 交付纪律

- 功能分支开发，开 PR 由 GitHub CI 自动跑质量门禁（见「常用命令」CI 条目），
  全绿后合并；不直接推默认分支。本地 no-mistakes 闸门已于 2026-08-29 移除
  （补充拍板 #21），不再跑 `/no-mistakes`。
- 测试 fixture 密钥不进仓库（testing.md）。
- 前端设计评审用 agent_browser 对
  `docs/design/prototype/`（零构建原型）截图；评审流程见
  `docs/design/spec.md` §7。

## 里程碑状态

- [x] M0 骨架 + spec：workspace、CI、LICENSE、docs/、设计规范 + 原型
- [x] M0 功能实现（核心库 + CLI 单机闭环）
- [x] M1 同步（BYO 变更发现 + CAS + 墓碑；`lk sync` / `lk config`；存储后端
  trait + 本地模拟/WebDAV/S3 实现；E2E `scripts/e2e_m1.sh`）
- [x] M1 并发结构（G1 根治）：同步轮次 = 抓取无锁 + 应用短锁两阶段；命令与
  后台同步并发，网络 I/O 不持守护进程锁；vault 内存用读写锁（权限层与数据层
  互斥解耦，见 docs/sync.md §2.3 与 `crates/lk-daemon/src/daemon/mod.rs` 的
  `SharedDaemon` 文档）
- [x] M1.5 插件化改造（Cordis）：lk-core A/B 层 trait 服务 + 事件总线
  （`crates/lk-core/src/service.rs` / `bus.rs`；密文格式/存储布局/IPC 协议零变更）；
  daemon 按 C 层边界拆模块并装配总线（现位于 `crates/lk-daemon/src/`，见下方
  M2 下沉条目）；D 层真 Cordis 宿主 + `frontend/src/cordis.yml` 装配（theme /
  ipc-bridge / preference-store / toast + 槽位骨架），事件契约见
  `frontend/src/events.ts`
- [x] M2 核心（Rust 授权门 + 推送通道 + daemon 下沉）：
  - C 层 daemon 宿主下沉到共享 crate **`crates/lk-daemon`**（决策 #2 A；
    `lk_daemon::run(dir)` CLI 入口 / `serve_embedded` 桌面内嵌入口）
  - 推送通道（决策 #3 A）：`transport::PushHub` + `notifier::Notifier`
    （EventSink），订阅连接收 JSON-RPC notification 帧（`subscribe` 方法）
  - 授权门（`lk-core/src/authz.rs`）：三层模型 + `ApprovalChannel` trait +
    `PendingApprovals`（30s 超时默认拒绝）；RPC 分发走**执行计划路由**
    （ADR-0001：`lk-daemon::router` 唯一分发点，三策略 Inline / OutsideLock /
    ApprovalDeferred；G1 锁纪律集中一处）
  - 启动者判定（`lk-core/src/starter.rs`）：IPC 对端 PID 进程链回溯
    （Linux procfs / Windows Toolhelp+PEB / macOS sysctl），失败 fail-closed
  - 规则库：`model::Rule`（含 name，决策 #6）+ `{uuid}.rule.lk` 密封 +
    `SealType::Rule` + 索引 `ObjectKind::Rule` + 与条目同路径同步
    （软删/墓碑/30 天硬删）；变更广播 `item.changed(kind="rule")`
  - IPC/CLI（决策 #6/#1）：`authz.evaluate` / `approval.result` /
    `rule.add|list|remove`（`approval.request` 已移除）；`lk rule add|list|remove`
    + `lk inject --keys <name...> -- <cmd>`（值只进子进程 env）
- [x] M2 桌面（Tauri 壳：内置守护实例/托盘/锁屏 WTS+CGSession/command 桥/通知
  订阅桥；approval 弹窗 + 30s 倒计时；ui-unlock/vault/rules/settings/audit
  五插件 + 锁态整页↔三栏切换；Windows Hello 置灰预留，决策 #5 B）
- [x] M2.5 首次初始化向导（首启门控：`vault.status.initialized` 无库→向导 /
  有库→解锁页；ui-onboarding 四步插件：设主密码(强度+一致) → 真实恢复码
  (仅 init 响应一次) → 完成解锁；主密码 ≥8 位策略留 Rust（vault.init/
  recover 校验，弱密码/已存在库 UI 统一文案）；浏览器 E2E 用
  `__LIGHTKEY_MOCK__.simulateFreshInstall()` + 重载模拟首启）
- [x] M2.75 跨子系统 stdio 桥（补充拍板 #14；规格 `docs/cross-subsystem.md`）：
  `lk.exe bridge` stdio 中继 + Linux `lk` local/bridge 传输抽象（`LIGHTKEY_BRIDGE`
  探测分型：装了连不上明确报错、没装静默本地，绝不静默回落防空库错觉；
  连接目标可见）+ 协议版本主.次校验 fail-closed（daemon.json 可选 version）；
  `lk-core::path_ns` 跨命名空间归一化（`wsl://<distro>/…` 规范形，两侧同函数）
  + 审计 `channel=wsl-bridge`；release 双产物（Linux `lk` + 桌面包捆绑
  `lk.exe`）；E2E `scripts/e2e_cross_subsystem.sh`（无 WSL 干净跳过）
- [x] M2.8 锁定态 inject 一体化（补充拍板 #19）：锁定态 `lk inject` 在桌面审批
  界面在场时折叠「临时解锁 + 本次授权」为一次交互（弹窗含主密码栏 + Allow/Deny）；
  headless 维持 fail-closed `session.invalid`；一体化**不签发会话令牌 / 不写
  session.token / 不置 shared.vault**（临时解锁材料只服务本次注入，不产生
  item.* 全量读能力，#65 配套）；协议加 `approval.result.masterPassword` + 
  `authz.request.needsUnlock`。见 `docs/authorization-gate.md` §5.1
- [x] M2.9 值披露裁决（补充拍板 #20，issue #65 主体）：安全边界修订为
  **产品接口面即边界**（令牌 = 认证 ≠ 授权）；`item.get` 走三层
  （读规则 → 弹窗 → 拒绝）、`item.export` 恒弹窗；桌面内嵌直调受信豁免；
  读规则能力类型（`Rule.capability`，projectDir + keys，无 command）；
  拒绝 = `authz.denied`（**-32017**，spec 原定 -32015 被 bridge 码占用）。
  实现规格 `docs/value-disclosure.md`（唯一出处；实现注记：read 规则 CLI
  形态 `--read --keys <name...>`）；#65 已关闭
- [x] M2.95 规则管理审批门 + 读通道一体化解锁（补充拍板 #22/#23，issue
  #104/#105）：`rule.add` / `rule.remove` 升为桌面审批门——对称原则
  （建立/撤销授权都是授权事件）；desktop 直调豁免、headless fail-closed
  （复用 -32017）、锁态 `session.invalid` 先行；`ApprovalKind::Rule`（serde
  `"rule"`，单一 kind + command 承载操作，remove 由 daemon 补全
  name/keys/projectDir 供弹窗）；ApprovalDeferred 三阶段 + **finalize 锁内
  TOCTOU 重校验**；审计全路径（失败路径新增）+ `channel=auto-approve`
  （E2E 自动批准，env 门控 `LIGHTKEY_E2E_AUTO_APPROVE=rule`，release 保留
  是有意决策，启动横幅）；CLI 规则门语境文案；前端 kind=rule 分支 + 未知
  kind 防御渲染。**读通道一体化解锁（#23）**：锁态 + 桌面 UI 在场时
  `item.get` / `item.export` 必弹「主密码 + 解锁并允许」窗（协议零新增：
  needsUnlock/masterPassword/kind 已就位），临时 vault 单次披露即毁、
  无痕（不签发令牌/不写 session.token/不置共享 vault，#65 边界）；锁态
  read 规则命中**也必弹**（规则在加密库内无法预载）；headless/未初始化库
  维持 fail-closed；等待期整库解锁 → finalize 常态路径、被锁 → session.invalid；
  「记住」按钮条件 `isRead && !needsUnlock`（D 层单测钉住；M2.97 扩为
  `(isRead || write put) && !needsUnlock`）。见
  `docs/authorization-gate.md` §5.2/§9、`docs/value-disclosure.md` §3/§5、
  `docs/decisions.md` #22/#23
- [x] M2.97 写入授权门（补充拍板 #24，2026-09-02 拍板；spec 唯一出处
  `docs/write-gate.md`）：`item.put`/`item.delete` 升裁决方法（写 = 授权
  事件）；写规则 `capability=write` + `actions`（serde 缺省 create+update，
  update 双向名称约束）；**delete 恒弹窗**任何规则不豁免；RPC 不拆（action
  由 daemon 从 `ItemPutParams.id` 有无权威派生）+ `ApprovalKind::Write`
  （serde `"write"`）；拒绝复用 -32017；desktop 直调豁免、headless
  fail-closed、锁态 `session.invalid` 先行（写门无一体化解锁窗，留档）；
  全路径审计 command 派生 `item.create/update/delete <name>`；
  `lk rule add --write`（actions 校验拒绝 delete）+ 写拒绝语境文案；
  前端 kind=write 弹窗（动作/条目名/projectDir/倒计时，不展示值）+
  「记住」仅 put（最小写规则 keys=[条目名]+actions=[create,update]）、
  delete 无记住；规则页展示 capability+actions、审计页 §8 口径；E2E 不扩
  auto-approve；同步应用不受门、真相源投毒为已知限制。issues #112-#115。
- [ ] M3 浏览器填充

## Agent skills

### Issue tracker

Issues are tracked as GitHub Issues on `github.com/jibuji/lightkey` via the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles use their default label strings (e.g. `needs-triage`, `ready-for-agent`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context: one `CONTEXT.md` + `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
