# 规则程序指纹绑定规格（identity-binding，M2.98）

- 状态：**已实现**（2026-09-02 identity-binding grilling-with-docs 会话收敛
  拍板；M2.98 PR A-D 序列经 PR CI 门禁落地——lk-core / lk-daemon / lk-cli+E2E /
  前端+收尾，issues #123/#124/#125/#126，父立项 #121）
- 关联：[authorization-gate.md](authorization-gate.md)（三层模型 / 规则 /
  §11 摘要）· [value-disclosure.md](value-disclosure.md)（读规则）·
  [write-gate.md](write-gate.md)（写规则；§9 曾把 exe+哈希留档为整体可选
  加固，本规格将其升级为正式立项）· [ipc.md](ipc.md) · [decisions.md](decisions.md)
  #25（拍板记录）。
- **本文是本项的唯一实现规格**；authorization-gate.md §11 只留摘要并指向这里。
- 术语：**程序指纹** 见 [CONTEXT.md](../CONTEXT.md)（区别于「启动者」——
  后者只用于审计与第 1 层兜底，不参与规则匹配）。

## 1. 问题

规则（inject / read / write）授权的是「项目目录 + 命令形态 / 条目名」，
**不包含"哪个可执行文件"维度**——任何同用户进程在授权目录内**复现授权命令
形态**即可命中规则：

- 注入：恶意程序在授权目录跑 `lk inject --keys NPM_TOKEN -- npm publish`，
  PATH 前置同名假 `npm` 即截获注入的 env；
- 读：目录内任意进程按 read 规则条目名静默 `item.get`；
- 写：目录内任意进程按 write 规则条目名静默覆盖（写门上线后）。

注意措辞：规则里**不存在身份可供"伪造"**——攻击者是在复现形态。用户期望
"我授权的是**这个程序**"，故引入程序指纹：规则显式声明可执行文件的
canonical 路径 + 内容哈希。

## 2. 目标与非目标

**目标**

1. 规则**可选**绑定程序指纹（canonical 路径 + SHA-256）；未绑定 = 现状语义
   （零迁移，如实降级）。
2. **注入规则**绑定**被注入命令的可执行文件**（`command[0]`）——本规格主
   线，直接闭合"命令形态冒充"；**读/写规则**可选绑定调用方链（仅显式启用，
   限独立工具二进制场景，终端/IDE/脚本场景如实声明绑定不了）。
3. 指纹失配 = **视同未命中** → 弹窗审批 → 弹窗提供「**以新指纹重新授权**」
   （复用规则管理审批门；不新增错误码、不新增协议面）。
4. 大文件哈希不拖慢裁决：**内存指纹缓存 + 元信息失效 + 阈值预计算 +
   size 快速失配门**（§6）。
5. 每次裁决（含失配路径）写审计。

**非目标（默认值已定，见 §12）**

- 防同用户**原生攻击**（就地改写授权二进制本身 = 她就是这个程序；与 #15/#20
  边界外同源，§8）；
- 代码签名验证（Windows Authenticode / macOS notary / Linux 无统一方案；
  供应链复杂度与跨平台不一致，不选）；
- macOS 平台本期 fail-closed 兜底（对端 env PATH 读取验证后落地，机制与
  `resolve_peer_cwd` 现状同口径）；
- 常驻进程持令牌（#68 观望）等既有关闭项不随本规格重开。

## 3. 判定矩阵

| 通道 | 方法 | 规则指纹绑定状态 | 匹配结果 |
|------|------|------------------|----------|
| 任意 | 全部 | **未绑定**（fingerprint=None） | 现状语义（目录+形态/条目名），零变化 |
| socket（持令牌，解锁态） | `inject`（绑定规则命中） | 路径 == exePath **且** SHA-256 == exeSha256 | 静默放行 + 审计 |
| socket | `inject` | 路径 ≠ exePath，或 size 不符，或哈希不符 | **视同未命中** → 弹窗（GUI 在场）→ allow/deny·timeout；headless → `authz.denied` |
| socket | `inject` | 失配且弹窗批准 | 本次放行；「以新指纹重新授权」→ 规则指纹更新（走规则门） |
| socket（**锁定态**） | — | — | `session.invalid` 先行（规则在加密库内；与 inject/读/写门同口径） |
| desktop（内嵌直调） | — | 不查（受信豁免；注入通道桌面直调也无豁免——指纹随注入路径整体裁决，不单独豁免） | 放行 |

- 启动者未知 / cwd 不可得 → 第 1 层 fail-closed 拒绝（与 inject 同口径，
  先于指纹比对）。
- 指纹失配**不引入新错误码**：与"未命中"完全同路径，headless 统一
  `authz.denied`（防探测——不给攻击者"规则存在但指纹不符"的枚举信号）；
  弹窗主题明示"程序指纹与规则不符（可能已更新）"，给人决策依据。

## 4. 规则 schema（可选扩展）

`crates/lk-core/src/model.rs` 的 `Rule` 增加一个可选字段（serde default =
`None`，旧规则零迁移、密文反序列化不受影响）：

```rust
pub struct Rule {
    pub id: Uuid,
    pub project_dir: String,
    pub name: String,
    pub command: String,
    pub keys: Vec<String>,
    pub capability: String,   // inject | read | write
    pub actions: Vec<String>, // M2.97 写门
    /// 程序指纹（M2.98，可选）：None = 现状语义；Some = 严格绑定。
    #[serde(default)]
    pub fingerprint: Option<ProgramFingerprint>,
    pub created: String,
}

pub struct ProgramFingerprint {
    /// canonical 绝对路径（daemon 侧解析/固化；展示与预筛用）。
    pub exe_path: String,
    /// SHA-256（hex，小写）；匹配的唯一安全依据。
    pub sha256: String,
    /// 固化时的文件字节数（size 快速失配门，§6-3）。
    pub size: u64,
}
```

- **能力语义**：
  - `capability=inject`：绑定 `command[0]` 解析出的可执行文件；
  - `capability=read/write`：可选绑定调用方链（starter 的 canonical
    exe，经既有进程链回溯）；仅**独立工具二进制**场景建议启用，终端/IDE/
    脚本场景 starter 不稳定（升级即失配）——文档明示局限；
  - 跨能力共用同一结构；`capability=inject` 时为必经校验维度的完整集。
- **兼容性**：`fingerprint` 带 `#[serde(default)]`；旧规则解析为 `None`；
  未绑定规则匹配函数路径零变化（`rule_matches` / `read_rule_matches` /
  写规则匹配在 fingerprint=None 时直接按现行逻辑短路）。
- **存储形态**：指纹存规则密文内（K_data），随规则对象同路径同步
  （`{uuid}.rule.lk`），指纹更新 = 规则更新（revision bump、CAS），无新机制。

## 5. 解析与比对（daemon 侧，信 daemon 不信客户端）

### 5.1 command[0] → canonical 路径

- daemon 读 IPC 对端**真实 env** 的 PATH（客户端自报一律视为不可信输入，
  与 starter/cwd 同原则）：
  - Linux：`/proc/<pid>/environ`（同用户可读）；
  - Windows：PEB `ProcessParameters.Environment`（复用 `starter.rs`
    已有 PEB 读取基建，同款偏移表 + 长度 sanity check）；
  - macOS：`sysctl KERN_PROCARGS2`（实现期验证权限与可达性；失败 →
    fail-closed，机制与 `resolve_peer_cwd` 现状同口径）。
- 按 PATH 序解析 `command[0]`（第一个命中项即候选）+ 对端真实 cwd 兜底
  （非绝对路径时）；结果为 canonical 绝对路径。
- 命令为绝对路径时免 PATH 解析（直接 canonicalize）。
- **PATH 前置假程序**（规则绑定场景）：候选路径 ≠ 规则 exePath → 直接视同
  未命中（无需哈希，见 §6-3 前先比路径）。

### 5.2 比对序（绑定规则）

1. 路径不一致 → 视同未命中（免哈希）；
2. size 与规则记录不符 → 视同未命中（免哈希，§6-3）；
3. 否则哈希比对（走缓存，§6）→ 一致命中 / 不一致视同未命中。

### 5.3 审批时的指纹来源

- 「以新指纹重新授权」与「允许并记住」的指纹**由 daemon 在审批 finalize
  侧解析/计算**（审批人点的是"这个程序"的当前形态；不信任客户端上报的
  路径/哈希）。

### 5.4 命令形态匹配（绑定规则，issue #132 回归钉住）

- 绑定规则的 `command` = CLI 推导的可执行 **basename**（`/usr/bin/npm` →
  `"npm"`，§11 PR C）；注入请求 `command` 是**完整命令串**（`lk inject --
  npm publish`）。匹配层对绑定规则按 `command[0]` 的**可执行名**（basename，
  去目录）与 `rule.command` glob 匹配；整串 glob 必失配——绑定规则永不命中、
  指纹门不可达（本规格 §2 目标 2 的「命中静默放行」与「失配 → 指纹不符弹窗」
  两条路径皆失效）。
- **未绑定（`fingerprint=None`）规则维持整串 glob 语义**（§4 兼容性零变化）。

## 6. 大文件与性能（拍板：指纹缓存 + 元信息失效 + 阈值）

SHA-256 对任意大小文件都只能**全量读一次**——优化空间在"多久算一次"，
不在"单次算多快"。方案：

1. **指纹缓存（内存，非持久化）**：daemon 进程内缓存
   `exe_path → {sha256, size, mtime, inode/文件索引}`。评估先 stat——
   元信息与快照一致 → 复用缓存哈希（**成本 = O(stat)，与文件大小无关**）；
   不一致 → 流式全量重算（1 MiB 块）并更新快照。
   **不落盘的原因**：落盘缓存可被同用户进程投毒成"自己二进制"的哈希——
   那正是要防的冒充；缓存只活在 daemon 内存、随守护进程会话生命周期。
2. **阈值 64 MiB（可配置）**：只决定**预计算时机**，不改变安全语义——
   ≤ 64 MiB：规则创建/审批 finalize 时**立即预计算**（锁内一次性，人在场
   可接受）；> 64 MiB：同样预计算，或惰性到首次命中（配置可选）；daemon
   重启后的首次缓存冷态 = 一次全量哈希（文档声明为一次性可接受阻塞，且
   Windows/Linux 下流式读 100 MiB 级二进制为百毫秒级，不引入 G1 违例的
   新路径——必要时把冷态哈希移到 `ApprovalDeferred` 的锁外等待窗口，列为
   实现优化项而非默认）。
3. **size 快速失配门**：比对序先比 size——与规则记录不符 → 视同未命中、
   免哈希（改内容必改大小的伪装才轮到哈希上场）。注意 size 相同、内容被
   改（就地覆盖同长）→ 元信息快照的 mtime 会变 → 触发重算 → 哈希失配。
4. **威胁前提（文档明示）**：本方案防"**冒充**"——PATH 前置假程序、同名
   假程序、复现命令形态；攻击者若能**就地改写授权二进制本身**（可同时
   恢复 mtime/内容）＝ 她就是这个程序，指纹绑定无能为力——该向量与同
   用户原生攻击同属边界外声明（decisions #15/#20）。元信息只做失效提示、
   不作安全依据，安全依据始终是 SHA-256 本身。

## 7. 指纹失配 UX（拍板：视同未命中 + 弹窗重新授权）

- **失配 = 未命中**：走与注入/读/写门一致的裁决路径——GUI 在场弹窗、
  headless `authz.denied`；**不新增错误码**（防探测：攻击者无法区分
  "无规则"与"规则存在但指纹不符"）。
- 弹窗主题：明示「程序指纹与规则不符（可能已更新）」+ 展示当前解析到的
  路径与哈希摘要（8 位前缀，不展示完整值）；按钮：
  - 「本次允许」（一次性放行，与普通审批一致）；
  - 「**以新指纹重新授权**」（追加指纹更新请求 → 规则管理审批门 →
    daemon finalize 侧重算指纹并落盘，审计 command=`rule.add/update`）；
  - 「拒绝」/ 超时默认拒绝。
- 升级/重装后的体验 = 一次弹窗交互重新授权，无命令级侧写变化。
- 「记住」按钮若用于读/写规则（均有「允许并为此项目记住」先例），记住的
  内容在指纹绑定规则上 = **指纹 + 条目名/mini 规则**，最终由 daemon 侧
  计算（§5.3）。

## 8. TOCTOU 与边界（拍板：接受 + 文档声明）

- 校验通过后、子进程 spawn 前被换文件的竞态窗口：按 §1 威胁模型分析——
  攻击者 PATH 指向自有程序 → 哈希在匹配层已失配；攻击者就地改写授权
  二进制 → §6-4 边界外。**接受，不额外加固**；不做"daemon 返回指纹由
  CLI spawn 前复核"的伪强加固（CLI 是同用户不可信方，复核无意义）。
- 其余边界与 [write-gate.md](write-gate.md) §9 对齐：同步应用不受门、
  真相源投毒口径不变、同用户原生攻击边界外。

## 9. 已知限制

- 未绑定指纹的规则维持现状（如实降级）；绑定是**加固选项**而非新能力面。
- 升级/重装导致指纹失配频率由 §7 一次交互解除；跨平台（macOS）首期
  fail-closed 意味着该平台指纹绑定规则在 env 读取不可用时按未命中处理。
- 读/写规则的调用方链绑定仅限独立工具二进制场景（§4 能力语义），脚本
  场景不承诺。
- 冷启动（daemon 重启后的首次命中）一次全量哈希（§6-2，可配置移到锁外）。

## 10. 测试计划（TDD，先红后绿）

1. 单元（lk-core）：
   - `fingerprint` serde 往返 + 缺省 `None`；旧规则 JSON（无字段）→ None；
   - 比对序：路径不符免哈希 / size 不符免哈希 / 哈希一致命中 / 不一致失配；
   - PATH 解析候选序：前置假程序场景（候选序靠前但 ≠ 规则 exePath → 失配）；
     绝对路径免解析；
   - 流式哈希：大文件（≥64 MiB 基准）内存占用断言（块式读取，不高驻全量）；
   - read/write 指纹绑定仅显式启用（默认不校验）。
2. 集成（lk-daemon，`tests/identity_binding.rs`，先红）：
   - 绑定规则命中 → 静默放行 + 审计；失配 → NeedsApproval 路径 + 弹窗主题
     「指纹不符」；headless 失配 → `authz.denied`（与未命中同码断言）；
   - 「以新指纹重新授权」→ 规则门弹窗批准 → 落盘新指纹 + 审计（command=
     rule.add/update）；
   - 缓存：元信息一致复用（stat 计数断言）；内容改 + mtime 变 → 重算 → 失配；
     内容改 + size/mtime 恢复 → 重算 → 失配（size 同长场景）；
   - macOS 平台 env 读取失败 → fail-closed（cfg 门测试）；
   - 锁态 → `session.invalid`（回归）；启动者未知 → 第 1 层拒绝（回归）。
3. E2E（脚本扩展）：headless 失配拒绝 + 审计；绑定规则命中静默；**不扩展**
   auto-approve 到指纹通道（沿用写门口径）。
4. 前端（vitest）：弹窗「指纹已更新」提示 + 「以新指纹重新授权」按钮渲染/
   触发（仅绑定规则命中失配的审批帧）；未知字段防御渲染。

## 11. 交付切分

建议 PR 序列（各自出口全绿，走 PR CI 门禁）——**已按此序列全部落地**：

1. **PR A（lk-core，#123）**：`ProgramFingerprint` + `Rule.fingerprint`（serde
   default）+ 比对序与匹配 + PATH 解析纯函数 + 流式哈希工具 + 单测（§10.1）；
2. **PR B（lk-daemon，#124）**：对端 env PATH 读取（Linux/Windows 本期，
   macOS fail-closed）+ 内存指纹缓存/元信息失效 + 审批 finalize 侧指纹
   计算 + 失配路径/弹窗主题 + 集成测试（§10.2）；
3. **PR C（lk-cli + E2E，#125）**：`lk rule add --fingerprint <exePath>`（与
   `--read`/`--write` 同款省略 command，命令由可执行文件 basename 推导）、
   失配文案、脚本扩展（§10.3）；
4. **PR D（前端 + 收尾，#126）**：弹窗指纹主题 + 重新授权按钮 + vitest +
   文档收口（authorization-gate §11 状态翻转「已实现」、ipc/cli/agent-cli/
   data-model/milestones、decisions #25 状态翻转、issue 立项关闭）。

## 12. 开放问题（默认值已定，改动需重新拍板）

- **阈值数值**：默认 64 MiB（可配置）；不改变安全语义，只影响预计算时机。
- **read/write 的调用方链绑定 CLI 形态**：默认只随注入路径落地完整
  CLI/UI；read/write 仅字段预留 + 文档明示适用边界（独立工具二进制）。
- **指纹随同步**：指纹是规则字段，随规则对象同步，无新机制（§4）。
- **弹窗合并去重 + 每 starter 并发上限**：沿用 value-disclosure §12 /
  write-gate §12 留档，不阻塞本规格。
- **macOS env 读取**：实现期验证 `KERN_PROCARGS2` 权限；不可行则 macOS
  指纹绑定规则 fail-closed（视同未命中），文档如实声明。