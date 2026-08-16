# M1.5 插件化改造 · 双轴代码审查报告

- 审查对象：`git diff eb74f28...602215c`（PR #16，M1.5 全量）。
- 提交：`602215c M1.5 插件化改造（Cordis）：A/B 层 trait 服务 + 事件总线 + D 层 Cordis 宿主 (#16)`。
- 结论：**无严重（需裁决）项**；发现 2 普通 + 若干建议，已全部当场修复并回归验证。
- 回归验证（修复后）：`cargo test`（78 单测 + 9 属性 + 1 同步属性 + 2 daemon）全绿；
  `cargo clippy --all-targets` 无警告；`cargo fmt --all -- --check` 通过；
  `frontend npm test`（16 用例）全绿；`npm run build`（tsc + vite）通过。

---

## 轴 1 · 规格轴（Spec）

逐条对照 `docs/milestones.md` M1.5 节、`docs/plugin-architecture.md`（D16 定案）、
`docs/architecture.md`、`docs/decisions.md` D16、`docs/design/spec.md` §2/§3/§5。

### 结论概览

- **范围完整，无 scope creep**：四层 A/B/C/D 边界重组、trait 服务 + 事件总线、C 层 daemon
  装配、D 层真 Cordis 宿主 + 首批插件（theme / ipc-bridge / preference-store / toast /
  槽位骨架）均按规格落地。额外出现的 `ctx.toast`（§5.2 `clipboard.copied` 监听者）、
  `ctx.nav`（§6.1 content「路由骨架」）、`ctx.session`（§5.3 事件翻译路径）均是
  出口标准/契约明确要求的，非越界。
- **行为不回归达成**：M0/M1 全量测试 + 属性测试在重组后全绿；`vault.rs` 仅新增
  `bus: Option<Arc<EventBus>>` 字段与广播调用，密文格式/存储布局/IPC 协议零变更。
- **事件总线契约齐全**：`item.changed`（三方响应）/ `session.unlocked` / `session.locked` /
  `theme.changed` / `clipboard.copied` 均实现并有单测/属性测试；`authz.request` 按规格
  留待 M2（仅 TS 侧声明契约）。

### 发现

| # | 严重级 | 位置（合并态 602215c） | 说明 | 处置 |
|---|--------|------------------------|------|------|
| SP-1 | 建议 | `crates/lk-core/src/bus.rs:15,76`、`frontend/src/events.ts:25` | Rust `VaultEvent::ItemChanged` 字段名 `kind` 与规格 §5.2 协议字段 `type` 字面不一致；`events.ts:25` 注释「与 Rust `VaultEvent::ItemChanged` 字段对齐」误导（字面未对齐：`item_id`/`revision_date`/`kind` vs `itemId`/`revisionDate`/`type`）。`type` 是 Rust 关键字，用 `kind` 是合理工程取舍；M1.5 内 Rust 事件不出进程，无运行时影响，但 M2 IPC 通知桥序列化时必须映射 `kind → type`。 | 已修复：补文档注明映射（bus.rs 表 + 字段注释），改写 events.ts 注释为「语义对齐」。未改字段名（避免 `r#type` 原始标识符污染）。 |

规格逐条核对结论（无缺失）：

1. M1.5 范围「Rust A/B 层 trait 服务 + 事件总线（模拟 Cordis 语义）」→ `service.rs` / `bus.rs` ✅
2. 「C 层 daemon 宿主：装配 A/B、IPC 路由、空闲自动锁定、config.json 读写」→ `daemon/{mod,config,sync}.rs` ✅（config/sync 为原 daemon.rs 原样拆分，无逻辑变更）
3. 「D 层真 Cordis 4.x + cordis.yml + loader + @cordisjs/schema；首批 theme + ipc-bridge + preference-store；React 宿主薄层」→ ✅
4. 「槽位机制：topbar/sidebar/content 固定骨架 + slot 声明 + 布局数据」→ `Skeleton.tsx` + `slots.ts` + `cordis.yml` ✅
5. 出口「行为不回归」→ 测试全绿，密文/布局/IPC 零变更 ✅
6. 出口「D 层宿主可用：装配 + 槽位渲染 + 暗/浅切换 + 偏好持久化 + mock 适配器」→ ✅（测试覆盖）
7. 出口「事件总线：item.changed 三方、session 切换、theme 重渲染、clipboard Toast+30s 清除」→ ✅（单测 + 属性测试覆盖）

---

## 轴 2 · 合规性轴（Standards）

对照 `docs/architecture.md` / `docs/testing.md` / `AGENTS.md`（仓库规范）+
Fowler 坏味基线。工具已强制的（rustfmt/clippy/eslint/tsc）跳过。

| # | 严重级 | 位置（合并态 602215c） | 坏味/规范 | 说明 | 处置 |
|---|--------|------------------------|-----------|------|------|
| ST-1 | 普通 | `crates/lk-cli/src/daemon/mod.rs:356-357` | Duplicated Code（复制粘贴残留） | `lock_internal` 上方两行完全相同的文档注释。 | 已修复：删重复行。 |
| ST-2 | 建议 | `frontend/src/plugins/theme.ts:109-122` | Shotgun Surgery | 卸载清理硬编码 14 个 token 名，与 `THEME_PALETTES` 键重复；未来加 token 会漏清理。 | 已修复：遍历 `Object.keys(THEME_PALETTES.dark)`。 |
| SP-2 | 建议 | `frontend/src/plugins/toast.ts:31,39` | Duplicated Code / 魔法数字 | `30_000` 硬编码，未复用 `events.ts` 已导出的 `CLIPBOARD_CLEAR_MS`。 | 已修复：引入 `CLIPBOARD_CLEAR_MS`。 |
| ST-3 | 建议 | `frontend/src/host/loader.ts:12` | Mysterious Name（误导注释） | 文档引用 `frontend/cordis.yml`，实际文件为 `frontend/src/cordis.yml`。 | 已修复：更正路径。 |
| ST-4 | 建议 | `frontend/src/host/CordisHost.tsx:82,93-94` | 资源管理不对称 | `createHost` 的宿主服务插件（slots/nav）fiber 未纳入 `dispose`，卸载只遍历 loader 挂载的插件。 | 已修复：捕获 fiber 并 `dispose`。 |
| ST-5 | 建议 | `frontend/src/plugins/theme.ts:38-40`（近似） | 防御性缺失 | `preference.get(...) as ThemeName` 未校验存储值；损坏的 localStorage 主题值会使 `THEME_PALETTES[value]` 为 undefined 并抛异常。概率低、风险低。 | 未修（低价值；留作防御性改进）。 |
| ST-6 | 建议 | `frontend/vite.config.ts:20` | Speculative Generality | `assetsInclude: ["**/*.yml"]` 对 `?raw` 导入冗余（`?raw` 不依赖 assetsInclude）。无害。 | 未修（无害）。 |
| ST-7 | 建议 | `crates/lk-core/src/session.rs`（`invalidate_with`）/ `crates/lk-cli/src/daemon/mod.rs`（`vault_init(force)`、`shutdown`） | 语义小瑕疵 | 本就未解锁时（如强制重置、守护进程退出）也会广播 `session.locked`（幂等空锁信号）。fire-and-forget、锁屏场景幂等可接受。 | 未修（M2 接线时留意即可）。 |

---

## 修复清单（本分支）

- `crates/lk-cli/src/daemon/mod.rs`：删除重复文档注释（ST-1）。
- `crates/lk-core/src/bus.rs`：`ItemChanged` 文档表 + `kind` 字段注释注明 `kind → type` 协议映射（SP-1）。
- `frontend/src/events.ts`：`ItemChangedPayload` 注释改为「语义对齐」+ 字段映射说明（SP-1）。
- `frontend/src/plugins/toast.ts`：复用 `CLIPBOARD_CLEAR_MS`（SP-2）。
- `frontend/src/plugins/theme.ts`：卸载清理遍历 palette 键（ST-2）。
- `frontend/src/host/loader.ts`：更正 cordis.yml 路径注释（ST-3）。
- `frontend/src/host/CordisHost.tsx`：宿主服务 fiber 纳入 `dispose`（ST-4）。
