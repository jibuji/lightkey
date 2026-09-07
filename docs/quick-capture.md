# 快速保存规格（quick-capture，拟议 M2.99）

- 状态：**已拍板**（2026-09-07 · 补充拍板 #27，关联 issue #161）。五项决策点
  已按建议裁定于 §9；按 §10 PR 序列落地（PR A lk-app / PR B 前端 / PR C 阶段
  二可选）。本文是实现的唯一规格来源。
- 关联：[write-gate.md](write-gate.md)（桌面直调豁免/写门语义）·
  [authorization-gate.md](authorization-gate.md)（三层模型）·
  [ipc.md](ipc.md)（令牌 = 认证 ≠ 授权）· [data-model.md](data-model.md)
  （条目 schema/重名语义）· [design/spec.md](design/spec.md)（前端评审）·
  [milestones.md](milestones.md)（里程碑归属候选 M2.99，以拍板为准）。

## 1. 问题

用户复制了一个 API key / token / 密钥，想**一键**存进 LightKey。现状做这件事
需要：打开应用 → 点「新建」→ 选类型 → 填名称 → 把值粘贴进表单 → 保存——
5+ 次交互，且打断当前工作流。目标是把「复制完的 secret 入库」压缩到
**1 次点击 + 1 次命名**。

快速保存不是新数据通道：写能力已存在（`item.put`，M2.97 写门），本规格只做
**交互面**——把既有能力以最小权限、最少摩擦暴露给用户。

## 2. 目标与非目标

**目标**

1. 用户复制任意文本密钥后，经托盘一键（或应用内按钮）打开**快速保存面板**：
   值自动预填（读一次剪贴板），名称聚焦输入，回车落库。
2. 落库路径 = 现有 `item.put`（desktop 通道，写门受信豁免放行 + 审计），
   无协议变更、无新审批路径、无新依赖（`arboard` 已在 workspace）。
3. 锁态/未初始化态引导正确：锁态 → 打开主窗口解锁页（不弹窗、不留值），
   解锁完成后自动重冒快存面板；未初始化 → 指向首启向导。
4. 剪贴板只在用户**主动触发**快存时读取一次——不做持续监听（隐私最小化）。

**非目标（默认值已定，改动需重新拍板，§9）**

- 锁态一步式「主密码 + 保存」：**不做**（与 write-gate.md §12 留档
  「锁态写一体化默认不做」一致）；快存锁态只引导解锁。
- 剪贴板持续监听 + 系统通知被动提醒：**不做**（tauri-plugin-notification
  桌面端不发射点击事件——lk-app `approval_alert` 已有实证注释，通知点击
  无回调路径；且持续读取剪贴板隐私敏感）。
- 全局热键（`tauri-plugin-global-shortcut`）：**阶段二可选**（§7.1），本次
  不实现；注册系统级热键需设置项可配可关。
- secret 类型之外的批量导入/文件导入：不在本规格。

## 3. 用户流程

### 3.1 主路径 A —— 托盘一键保存

1. 用户复制 API key（剪贴板已有，与 LightKey 无关的内容）；
2. 点系统托盘 LightKey 图标 → 菜单「快速保存剪贴板…」；
3. 主窗口弹出（隐藏则显示 + 聚焦）→ **快速保存面板**：
   - 值 = 剪贴板文本（灰显、可编辑；空剪贴板 → 值留空并提示）；
   - 名称框自动聚焦；按内容启发建议名（§4.3；无匹配则留空）；
   - 类型固定 = `secret`；可选「用途」；勾选「保存后清空剪贴板」
     （**默认关**，§5）；
4. 输入名称 → 回车 / 点「保存」→ toast「已保存」+ 列表刷新并选中新条目。

> 交互成本：复制（本来就做了）→ 1 次点击 → 1 次输入 → 回车。

**锁态**：点菜单 → 显示主窗口解锁页 + toast「解锁后即可快速保存」；解锁成功
（`session.unlocked`）→ 自动弹出快存面板（pending 意图，§4.4）。
**未初始化**：显示主窗口 → 首启向导（vault 无库无从解锁，与现状 fail-closed
口径一致）。

### 3.2 补充路径 C —— 应用内「从剪贴板」按钮

主流程与 A 共用同一面板，仅入口不同：应用内顶部/列表区放入口按钮（或新建
表单内「从剪贴板填入」按钮）→ 打开同一快存面板。`navigator.clipboard.readText`
不可靠时统一走 `clipboard_read` command。

### 3.3 开发者旁路 E —— CLI 变体（拟议，可独立立项）

`lk item add secret --name <name> --clipboard`（值取剪贴板免敲）；写门照常
裁决（写规则命中静默 / 弹窗 / headless 拒绝，write-gate.md §3 不变）。
本规格只留形态，不随 M2.99 实现。

### 3.4 明确不做的流程（防回潮）

- **D 剪贴板监听 + 系统通知**：不做（§2 / lk-app approval_alert 注释实证
  通知点击无回调）。
- **F 浏览器扩展捕获**：M3 方向性备案（browser-fill.md 协议目前只有填充
  `fill.suggest`/`fill.retrieve`，捕获需新协议），不随本规格。

## 4. 技术设计

### 4.1 lk-app 壳（Rust）

**能力**（全部已在 workspace / 既有模式内，无新第三方依赖）：

- 托盘菜单新增「快速保存剪贴板…」（置于「显示主窗口」上方，分隔线下保持
  显示/锁定/退出）；选中 →
  1. `get_webview_window("main")`：`show()` + `unminimize()` + `set_focus()`
     （复用「显示主窗口」逻辑；决策 #4 A 关闭=隐藏语义不受影响）；
  2. `app.emit("lk-shell-quick-save", ())` 通知前端（与 `lk-notify` 推送
     通道不同源：这是**壳 → UI 的本地请求**，**不**进守护进程通知协议
     `NOTIFY_*`，不落审计）。
- 新 command `clipboard_read() -> Option<String>`：
  ```rust
  #[tauri::command]
  fn clipboard_read() -> Option<String> {
      let mut cb = arboard::Clipboard::new().ok()?;
      cb.get_text().ok()
  }
  ```
  `arboard.workspace = true` 已存在于根 Cargo.toml；lk-app 加一行依赖即可
  （lk-cli 同款用法，见 `lk-cli/src/clipboard.rs`）。空剪贴板 / 非文本
  内容（如图片）→ `null`，前端提示「剪贴板无文本，请手动粘贴」。
  - **平台注记**：Wayland 下剪贴板读取需要窗口焦点——托盘触发时窗口已
    show+focus（步骤 1），顺序保证；X11/Windows/macOS 无此限制；读取失败
    前端可回退 `navigator.clipboard.readText()`。

**不动的东西**：守护进程 JSON-RPC 协议、`item.put` 参数、写门判定矩阵、
审计口径——全部零变更。

### 4.2 前端（D 层）

- **事件**（`frontend/src/events.ts` 模块增强新增一条）：
  `"quick.save-request"(): void`——起点 = 壳（托盘）经 Tauri 事件接入；mock
  模式由 QA 钩子模拟。监听者 = ui-vault 快存面板。
- **接入**：`ipc-bridge`（`frontend/src/plugins/ipc-bridge.ts`）在 tauri 模式
  额外 `listen("lk-shell-quick-save")` → `ctx.emit("quick.save-request")`。
  这是本地壳事件，**不**经过 `NOTIFICATION_EVENTS` 翻译路径（该集合严格镜像
  守护进程通知协议，勿混入）。
- **快存面板（放 ui-vault 插件内，不新建插件）**：复用 `Modal` 与现有
  `<ItemForm>` 的 secret 分支场域，新增薄面板组件：
  - 打开时 `invoke("clipboard_read")` → 预填值；名称聚焦；
  - 保存 = `ctx.ipc.create(draft)`（`type:"secret"`）+ 复用
    `handleSaved`（toast / `setSelectedId` / reload）——保存、CAS、刷新、
    选中逻辑与现有新建表单同源，不复制；
  - 面板内嵌于 ui-vault，天然获得 `items`（重名检查 §4.3）与
    `session`（锁态引导 §4.4）上下文，无跨插件消息。
- **触发源汇总**：① 托盘事件（A）；② 应用内入口按钮（C，`e.g.` 列表头
  「新建」旁加「快速保存」图标按钮或新建表单内「从剪贴板填入」）；
  ③ mock/QA 钩子。

### 4.3 名称建议与重名

- **启发建议（纯前端，可单测，设置页开关可选）**：按值前缀匹配表给建议名，
  仅做输入框初值、用户可改；保守前缀表初版：
  `sk-` → `anthropic_api_key`？**不**——具体 provider 名映射易错，初版只做
  **结构提示**：`sk-*` / `ghp_*` / `github_pat_*` / `AKIA*` / `eyJ*`（JWT）/
  `xox[baprs]-*`（Slack）→ 对应 `api_key` / `github_token` / `aws_access_key` /
  `jwt_token` / `slack_token` 等静态建议名（用户编辑），无匹配 → 留空。
  （§9.3 拍板点：映射表范围与「可关」）
- **重名**：`data-model.md` 无名称唯一约束（名字即身份，重名合法）——保存前
  面板内**软提示**「已存在同名条目（N 个）」，不阻止（用户可改名或继续）；
  与 `item.list` 现有数据同源，无额外 IPC。

### 4.4 锁态与未初始化

- 打开面板前置检查（读 `ctx.session`）：
  - `session.initialized === false` → 切首启向导（宿主既有互斥门控）；
  - `!session.unlocked` → toast「解锁后即可快速保存」，置 `pendingQuickSave =
    true`，**不打开面板、不读剪贴板**（锁态不读值：值只在面板打开那一刻取，
    锁态下取不到也无需取）；
  - 已解锁 → 打开面板。
- `pendingQuickSave` 消费：ui-vault 监听 `session.unlocked` → flush（打开
  面板并清标记）。锁定（`session.locked`）→ 不清 pending（用户可重复解锁
  路径）？**拍板点 §9.2**：建议锁定不清、超时/换库才清——初版简单化：
  pending 只在「打开面板 / 解锁成功消费」后清除，锁定不清，等待期间用户
  手动关闭入口即清。
- **不触碰** write-gate.md §12 留档的「锁态写一体化」：不收集主密码、不做
  一步式保存（决策 #19 的一体化注入弹窗是该调用的专有形态，不延伸）。

### 4.5 不落库的旁路内容

快存面板的设计不改变写门（§5）与同步（同步应用阶段不经过 IPC，不受门，
write-gate.md §9 不变）。

## 5. 安全边界

1. **最小权限读取**：剪贴板只在用户主动触发快存（`quick.save-request` 或
   「从剪贴板」按钮）时读一次；无后台轮询、无监听、无启动时读取。
2. **值流**：剪贴板 → `clipboard_read` → webview 内存 → `item.put`
   （desktop 通道写门豁免，write-gate.md §3 矩阵第一行）→ 加密库。
   值不进入：日志、事件帧（`quick.save-request` 零负载）、审计
   （沿用 `item.create <name>` 脱敏口径）、系统通知。
3. **「保存后清空剪贴板」默认关**：剪贴板内容是用户从别处复制的，非
   LightKey 复制出去的（30s 清除语义只适用于 LightKey 写入剪贴板的内容，
   browser-fill.md §2）；勾选开启时才置空（复用 arboard `set_text("")`
   语义，`lk-cli/src/clipboard.rs` 同款）。toast 提示「勾选保存后清空可避免
   明文残留」。
4. **锁态不读值**：锁态打开入口不读剪贴板、不留值（§4.4），与
   「锁态 fail-closed」语义同向。
5. **写门不被削弱**：CLI / wsl-bridge 通道的写裁决（规则/弹窗/拒绝）零变更；
   desktop 豁免是既有语义（放行 + 审计 allowed），不是新开后门。
6. 同用户原生攻击边界（调试器/内存注入）声明不变（#15/#17/#18/#20 口径）。

## 6. 审计

无新增审计事件：保存路径即现有桌面直调 `item.put`，审计
`item.create <name>`（command 派生，channel=desktop）已覆盖。托盘入口
本身（打开面板）不落审计——它不产生数据变更；如需「快速保存入口使用」可
扩展（§9.4 拍板点问询，默认不记）。

## 7. 阶段二（可选，另行立项）

1. **B 全局热键**：`tauri-plugin-global-shortcut` 注册（拟 `Ctrl+Shift+L`）→
   同 `quick.save-request` 路径；设置页（ui-settings）提供开关 + 改键；
   注册冲突可感知（attempts 失败提示）。跨平台差异：macOS 需辅助功能权限
   场景留档。
2. **E CLI**：`lk item add --clipboard`（§3.3），随 lk-cli 独立 PR。

## 8. 测试计划（TDD 草案）

1. 前端（vitest，mock 适配器）：
   - 快存面板：`quick.save-request` 事件 → 面板打开；mock 剪贴板注入值 →
     预填；名称聚焦；启发建议矩阵（前缀 → 建议名；无匹配 → 空）；
   - 保存 = `ctx.ipc.create` secret draft + `handleSaved` 语义（toast /
     选中 / reload）；CAS 冲突走既有 `handleConflict`；
   - 重名软提示（items 中有同名 → 提示出现，不阻止）；
   - 锁态：`!session.unlocked` → 不打开面板、不读剪贴板、pending 置位；
     `session.unlocked` flush 后打开；`initialized=false` → 不打开；
   - 「保存后清空剪贴板」勾选 → mock clipboard write 空串断言。
   - 事件契约：`quick.save-request` 进 events.ts 增强 + 单测（mock 钩子驱动）。
2. lk-app：`clipboard_read` 依赖系统剪贴板（arboard），CI 不可测——与
   lk-cli clipboard.rs 同口径，不做 Rust 单测；托盘菜单项存在性纳入壳的
   手工验收清单（Windows 主导，补充拍板 #4）。
3. E2E：浏览器 mock（`__LIGHTKEY_MOCK__`）驱动
   「入口 → 面板 → 保存 → item.changed 刷新」闭环；托盘真实链路列为
   桌面手工验收（跨子系统 Runbook 同款结构）。

## 9. 拍板记录（补充拍板 #27，2026-09-07 · 海盗王按建议裁定；记录于 decisions.md）

1. **锁态一步式「主密码 + 保存」**：**已定——不做**（与 write-gate.md §12
   留档一致）；锁态只引导解锁 + pending flush。
2. **pending 生命周期**：**已定**——锁定不清、面板消费 / 解锁成功消费后清。
3. **名称启发建议**：**已定**——保守前缀表（§4.3）内置、设置页可关（默认开）。
4. **入口落审计**：**已定——不记**（审计模型按数据变更事件，不记 UI 入口）。
5. **里程碑归属**：**已定——M2.99（快速保存）**，插入 M2.98 之后、M3 之前。

## 10. 交付切分（拟议 PR 序列，各出口全绿）

1. **PR A（lk-app）**：托盘菜单项 + `lk-shell-quick-save` emit + 窗口
   show/focus + `clipboard_read` command（arboard 依赖入 lk-app）。
2. **PR B（前端 + 收尾）**：`quick.save-request` 事件 + ipc-bridge 接入
   （tauri listen / mock 钩子）+ ui-vault 快存面板 + 重名软提示 + 锁态
   pending flush + vitest（§8）+ 文档收口（README 地图翻转「已拍板」、
   decisions.md 记 #161 拍板结论、milestones.md 标 M2.99 完成、CONTEXT.md
   术语条目「快速保存」）。
3. **PR C（阶段二，独立立项）**：全局热键（B）/ `item add --clipboard`（E）。