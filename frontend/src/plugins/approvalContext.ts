/**
 * 审批帧单一解析器（issue #147：审批帧携带门事实 + 前端单一解析器）。
 *
 * `authz.request` 帧自带门事实（`subKind`，daemon 权威派生），本模块把帧
 * 解析成**唯一事实对象** [`ApprovalContext`]：弹窗渲染、「记住 / 以新指纹
 * 重新授权」按钮、决策回调全部消费它——组件不再用 command 前缀匹配推断
 * 门语义（启发式全删）。
 *
 * - **rememberable 纯派生**：由 `subKind + writeAction + needsUnlock` 在
 *   本模块单点算出（**不进协议**——派生值进帧即同一真相存两处），按钮
 *   渲染条件与规则负载构造（[`buildRememberRule`]）消费同一解析产物，
 *   永不分歧；
 * - **严格解析**：`subKind` 只接受白名单精确值（镜像 Rust
 *   `ApprovalSubKind` serde 值 = `APPROVAL_SUB_KINDS`）；缺失/畸形 → null
 *   （旧帧信号）。旧帧（缺 subKind）下「记住」按钮**不再渲染**（原为可点
 *   但每次点击提示失败）——与「未知 kind 防御渲染」先例一致，spec 唯一
 *   行为修正；
 * - **结构化决策**：决策回调收单个 [`ApprovalResolution`] 对象
 *   （allow/deny + masterPassword + remember/reauthorize 意图），不再有
 *   尾随位置可选参——接口不随门特性每加一个参数。
 *
 * 本模块为纯函数（无 React / 无 IPC 依赖），单测钉行为
 * （`__tests__/approvalContext.test.ts`）。
 */

import type { AuthzRequestPayload } from "../events";
import type { RuleInput } from "../types";
import { APPROVAL_KINDS, APPROVAL_SUB_KINDS } from "../ipc/protocol";

/** 解析后的审批类型（补充拍板 #22 增 `rule`；M2.97 写门 #24 增 `write`）。
 *  白名单单一来源 = `ipc/protocol.ts` 的 `APPROVAL_KINDS`（镜像 Rust
 *  `ApprovalKind` serde 值）。未知/缺失 → `"unknown"` **防御性渲染**（明确
 *  提示，不回退按 inject 渲染——协议演进时旧 UI 不误导，规格 #102 故事 25）。 */
export type ApprovalKindValue = (typeof APPROVAL_KINDS)[keyof typeof APPROVAL_KINDS];
export type ParsedKind = ApprovalKindValue | "unknown";

/** 审批子类型白名单值（镜像 Rust `ApprovalSubKind` serde 值 =
 *  `APPROVAL_SUB_KINDS`：rule.add / rule.remove / item.put / item.delete）。 */
export type ApprovalSubKindValue =
  (typeof APPROVAL_SUB_KINDS)[keyof typeof APPROVAL_SUB_KINDS];

const KIND_WHITELIST: readonly string[] = Object.values(APPROVAL_KINDS);
const SUB_KIND_WHITELIST: readonly string[] = Object.values(APPROVAL_SUB_KINDS);

/** 解析审批类型 `kind`（未知/缺失 → "unknown" 防御渲染）。 */
export function parseApprovalKind(raw: unknown): ParsedKind {
  return typeof raw === "string" && KIND_WHITELIST.includes(raw)
    ? (raw as ParsedKind)
    : "unknown";
}

/** 严格解析审批子类型 `subKind`（issue #147）：只接受白名单精确值；
 *  缺失/畸形/未知 → null（旧帧信号——rememberable 派生恒 false，「记住」
 *  按钮不渲染）。 */
export function parseApprovalSubKind(raw: unknown): ApprovalSubKindValue | null {
  return typeof raw === "string" && SUB_KIND_WHITELIST.includes(raw)
    ? (raw as ApprovalSubKindValue)
    : null;
}

/** 程序指纹失配展示信息（M2.98，identity-binding.md §7）。 */
export interface FingerprintMismatchInfo {
  /** 当前解析到的 canonical 绝对路径（daemon 侧重算；展示用，非安全依据）。 */
  resolvedExePath: string;
  /** 8 位 SHA-256 前缀摘要（hex 小写；不展示完整值）。 */
  sha256Short: string;
}

/** 防御解析 `authz.request` 帧的可选 `fingerprintMismatch` 字段（未知字段
 *  防御渲染，AC「未知 kind/字段防御」）：只接受 shape 为
 *  `{resolvedExePath: 非空字符串, sha256Short: string}` 的值；畸形/缺字段/
 *  类型不符 → null（弹窗按普通 inject 审批渲染，不 crash、不渲染失配主题，
 *  无重新授权按钮）。`sha256Short` 超长（协议外完整哈希）→ **截断到 8 位**
 *  ——UI 硬保证绝不展示完整哈希值（identity-binding.md §7「不展示完整值」）。 */
export function parseFingerprintMismatch(
  raw: AuthzRequestPayload["fingerprintMismatch"],
): FingerprintMismatchInfo | null {
  if (!raw || typeof raw !== "object") return null;
  const rec = raw as Record<string, unknown>;
  if (typeof rec.resolvedExePath !== "string" || rec.resolvedExePath.length === 0) return null;
  if (typeof rec.sha256Short !== "string" || rec.sha256Short.length === 0) return null;
  return {
    resolvedExePath: rec.resolvedExePath,
    sha256Short: rec.sha256Short.slice(0, 8),
  };
}

/** 防御解析写帧的 `writeAction`（#137 最小授权修复）：daemon 从
 *  `ItemPutParams.id` 有无权威派生并随 kind=write 帧回带（RPC 不拆）。
 *  只接受 `"create"` / `"update"`；缺失/畸形（旧守护进程帧、类型不符）→
 *  null——**不生成记住规则**（宁可不记，不超发 `actions` 授权）。 */
export function parseWriteAction(
  raw: AuthzRequestPayload["writeAction"],
): "create" | "update" | null {
  return raw === "create" || raw === "update" ? raw : null;
}

/** 审批帧的单一事实对象（issue #147）：弹窗渲染、「记住 / 以新指纹重新
 *  授权」按钮与决策回调全部消费本对象；门语义一律从帧字段解析/纯派生，
 *  组件不再做 command 前缀匹配。 */
export interface ApprovalContext {
  /** 审批类型（未知/缺失 → "unknown" 防御渲染）。 */
  kind: ParsedKind;
  /** 审批子类型（严格白名单解析；read/export/inject 帧与旧帧 → null）。 */
  subKind: ApprovalSubKindValue | null;
  /** 写动作（#137 daemon 权威派生；缺失/畸形 → null）。 */
  writeAction: "create" | "update" | null;
  /** 锁定态一体化（#67）：须同时收集主密码。 */
  needsUnlock: boolean;
  /** 程序指纹失配信息（M2.98；畸形/未失配 → null）。 */
  fingerprintMismatch: FingerprintMismatchInfo | null;
  /** 规则门移除操作（subKind=rule.remove）。旧帧（缺 subKind）恒 false。 */
  isRuleRemove: boolean;
  /** 写门删除操作（subKind=item.delete，恒弹窗语义）。旧帧恒 false。 */
  isWriteDelete: boolean;
  /** 「允许并为此项目记住」可记性：**纯派生**（subKind + writeAction +
   *  needsUnlock），不进协议。规则构造（buildRememberRule）消费同一派生，
   *  按钮渲染与规则负载永不分歧。旧帧（缺 subKind）恒 false——spec 唯一
   *  行为修正（原为可点但每次点击提示失败）。 */
  rememberable: boolean;
  /** 「以新指纹重新授权」可用性：失配帧且非一体化解锁（临时 vault 无法
   *  持久化规则，daemon 失配帧恒 needs_unlock=false，防御保持）。 */
  reauthorizable: boolean;
}

/** 把 `authz.request` 帧解析成唯一事实对象（纯函数；弹窗入队时解析一次，
 *  渲染与决策回调全程复用）。 */
export function parseApprovalContext(req: AuthzRequestPayload): ApprovalContext {
  const kind = parseApprovalKind(req.kind);
  const subKind = parseApprovalSubKind(req.subKind);
  const writeAction = parseWriteAction(req.writeAction);
  const needsUnlock = req.needsUnlock === true;
  const fingerprintMismatch = parseFingerprintMismatch(req.fingerprintMismatch);
  const isRuleRemove = subKind === APPROVAL_SUB_KINDS.RULE_REMOVE;
  const isWriteDelete = subKind === APPROVAL_SUB_KINDS.ITEM_DELETE;
  // rememberable 纯派生（单点真相）：
  // - read（M2.9 值披露）：追加 read 规则；
  // - write put（M2.97 写门）：仅当 daemon 权威派生的 writeAction 在场
  //   （缺失/畸形 → 宁可不记，不超发全类授权）；
  // - export / delete 恒弹窗语义 → 不提供；锁态一体化（#23）临时 vault
  //   无法持久化规则 → 不提供；旧帧（缺 subKind）→ 不提供（#147 唯一
  //   行为修正：不再渲染可点但必失败的按钮）。
  const isRead = kind === APPROVAL_KINDS.READ;
  const isWritePut = kind === APPROVAL_KINDS.WRITE && subKind === APPROVAL_SUB_KINDS.ITEM_PUT;
  const rememberable = !needsUnlock && (isRead || (isWritePut && writeAction !== null));
  const reauthorizable = fingerprintMismatch !== null && !needsUnlock;
  return {
    kind,
    subKind,
    writeAction,
    needsUnlock,
    fingerprintMismatch,
    isRuleRemove,
    isWriteDelete,
    rememberable,
    reauthorizable,
  };
}

/** 决策值（结构化决策回调的字段；超时不回传——守护进程侧产生）。 */
export type ApprovalDecisionValue = "allowed" | "denied";

/** 结构化决策对象（issue #147）：决策回调收单个对象，不再有尾随位置
 *  可选参——接口不随门特性每加一个参数。 */
export interface ApprovalResolution {
  decision: ApprovalDecisionValue;
  /** 锁定态一体化（#67 needsUnlock 帧）：主密码（临时解锁 + 本次授权
   *  一次交互；不签发会话令牌——#65 边界）。 */
  masterPassword?: string;
  /** 「允许并为此项目记住」意图（仅 rememberable 帧的按钮发出）。 */
  remember?: boolean;
  /** 「以新指纹重新授权」意图（仅 reauthorizable 帧的按钮发出）。 */
  reauthorize?: boolean;
}

/** 可执行文件 basename（跨 Windows/Linux 分隔符）；「以新指纹重新授权」
 *  生成规则名/绑定 command 用（`fp-<basename>`，如 `fp-npm.cmd`）。 */
export function exeBasename(p: string): string {
  const parts = p.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last.length > 0 ? last : p;
}

/** 「允许并为此项目记住」的规则负载（解析器旁纯函数；host 只做意图→RPC
 *  翻译）。消费与按钮渲染**同一** ApprovalContext——渲染条件与规则构造
 *  永不分歧。`rememberable=false`（含旧帧 / delete / export / 锁态 /
 *  writeAction 缺失）→ null（宁可不记，不超发授权）。
 *
 *  负载口径：read → capability=read、keys=[条目名]；write put →
 *  capability=write、keys=[条目名] + actions=[帧内 writeAction 当前动作]
 *  （#137 最小授权：批准一次 create 只授 create）。 */
export function buildRememberRule(
  req: AuthzRequestPayload,
  ctx: ApprovalContext,
): RuleInput | null {
  if (!ctx.rememberable || req.keys.length === 0) return null;
  if (ctx.kind === APPROVAL_KINDS.READ) {
    return {
      projectDir: req.projectDir,
      name: `read-${req.keys[0] ?? "item"}`,
      command: "",
      keys: req.keys,
      capability: "read",
    };
  }
  if (ctx.kind === APPROVAL_KINDS.WRITE && ctx.writeAction !== null) {
    return {
      projectDir: req.projectDir,
      name: `write-${req.keys[0] ?? "item"}`,
      command: "",
      keys: req.keys,
      capability: "write",
      actions: [ctx.writeAction],
    };
  }
  return null;
}

/** 「以新指纹重新授权」的规则负载（解析器旁纯函数；M2.98
 *  identity-binding.md §7）：= 允许本次 + rule.add 携带
 *  `fingerprint{exePath}`（仅声明「绑哪个 exe」，daemon finalize 侧重算
 *  sha/size 固化，不信任客户端上报）。`reauthorizable=false` → null。
 *  name 由 exe basename 派生（`fp-<basename>`）；capability=inject（指纹
 *  只随注入规则绑定）；command = 被绑定 exe 的 basename（identity-binding.md
 *  §5.4，issue #136——不能回带审批帧的完整命令串，否则 daemon 侧若不规范
 *  化即死规则；daemon 落库侧仍会单点规范化）。 */
export function buildReauthorizeRule(
  req: AuthzRequestPayload,
  ctx: ApprovalContext,
): RuleInput | null {
  if (!ctx.reauthorizable) return null;
  const mm = ctx.fingerprintMismatch;
  if (!mm) return null;
  return {
    projectDir: req.projectDir,
    name: `fp-${exeBasename(mm.resolvedExePath)}`,
    command: exeBasename(mm.resolvedExePath),
    keys: req.keys,
    capability: "inject",
    fingerprint: { exePath: mm.resolvedExePath },
  };
}
