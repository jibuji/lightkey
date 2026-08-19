/**
 * IPC 接口层 —— LightKey 前端与本地守护进程（lk daemon）的 JSON-RPC 2.0
 * 协议面（docs/ipc.md）。本层只声明协议形状，不实现传输。
 *
 * 方法名对照 docs/ipc.md §4：
 *   status   → vault.status（含 initialized：库是否已初始化，M2.5 首启门控）
 *   init     → vault.init（建库；恢复码仅一次返回）
 *   unlock   → vault.unlock        lock → vault.lock
 *   list     → item.list           get    → item.get
 *   create/update → item.put（无 id 新建 / 带 expectedRevision 整条替换）   remove → item.delete
 *   syncStatus → sync.status       syncTrigger → sync.trigger
 *   auditList  → audit.list
 *   ruleList/ruleCreate/ruleRemove → rule.*（M2 骨架）
 *
 * 会话令牌（D10 §3）：由适配器持有，随解锁轮换；锁定后立即失效。
 * 错误语义：
 *   - 主密码错误 / 库未初始化 → Error("vault.invalid")（统一文案，防探测）
 *   - 会话失效 → Error("session.invalid")
 *   - CAS 冲突 → ConflictError（UI 提示「条目已被其他设备修改」覆盖/取消）
 */

import type {
  AuditEvent,
  AuthRule,
  ConfigPatch,
  ConfigView,
  Item,
  ItemDraft,
  ItemSummary,
  RuleInput,
  SyncStatus,
} from "../types";

export class ConflictError extends Error {
  constructor() {
    super("item.conflict");
    this.name = "ConflictError";
  }
}

export class VaultInvalidError extends Error {
  constructor() {
    super("vault.invalid");
    this.name = "VaultInvalidError";
  }
}

export class SessionInvalidError extends Error {
  constructor() {
    super("session.invalid");
    this.name = "SessionInvalidError";
  }
}

export interface UpdateOptions {
  /** 乐观并发（CAS）：传该条目加载时的 revision，不匹配则抛 ConflictError */
  expectedRevision?: string;
}

/** JSON-RPC notification 帧（守护进程推送；无 id，`docs/ipc.md` 决策 #3 A）。 */
export interface NotificationFrame {
  jsonrpc?: string;
  /** 事件名：item.changed / session.unlocked / session.locked / authz.request。 */
  method: string;
  /** 事件负载（最小字段，无密钥值；`docs/plugin-architecture.md` §5.2）。 */
  params: Record<string, unknown>;
}

export interface LightKeyIpc {
  /** 适配器种类（mock = 内存模拟；tauri = 真实守护进程桥）。 */
  readonly kind: "mock" | "tauri";

  /** vault.status：解锁态、库是否已初始化（无库 = 首启 → 初始化向导）、同步水位 */
  status(): Promise<{ unlocked: boolean; initialized: boolean }>;
  /** vault.unlock：主密码解锁；错误统一为 VaultInvalidError */
  unlock(masterPassword: string): Promise<void>;
  /** vault.init：建库（设主密码 + 生成恢复码/信封）；恢复码仅此一次返回 */
  init(masterPassword: string): Promise<{ recoveryCode: string }>;
  /** vault.lock：立即锁定（内存密钥擦除） */
  lock(): Promise<void>;
  /** vault.recover：恢复码 + 新主密码 → 新恢复码（仅展示一次） */
  recover(recoveryCode: string, newPassword: string): Promise<{ recoveryCode: string }>;

  /** item.list：解密态最小索引 */
  list(): Promise<ItemSummary[]>;
  /** item.get：单条完整解密条目 */
  get(id: string): Promise<Item>;
  /** item.create：新建 */
  create(draft: ItemDraft): Promise<Item>;
  /** item.update：整条替换，CAS；冲突抛 ConflictError */
  update(id: string, draft: ItemDraft, opts?: UpdateOptions): Promise<Item>;
  /** item.delete：软删除（墓碑，30 天硬删） */
  remove(id: string): Promise<void>;

  /** sync.status / sync.trigger */
  syncStatus(): Promise<SyncStatus>;
  syncTrigger(): Promise<SyncStatus>;

  /** audit.list（审计事件流；无密钥值） */
  auditList(): Promise<AuditEvent[]>;

  /** rule.*（决策 #6：`rule.add|list|remove`；规则含 name） */
  ruleList(): Promise<AuthRule[]>;
  ruleAdd(input: RuleInput): Promise<AuthRule>;
  ruleRemove(id: string): Promise<void>;

  /** approval.result：审批回传（allowed | denied；超时由守护进程侧产生） */
  approvalResult(
    requestId: string,
    decision: "allowed" | "denied",
  ): Promise<{ accepted: boolean }>;

  /** config.get / config.set（ui-settings；config.json 非敏感运行时配置） */
  configGet(): Promise<ConfigView>;
  configSet(patch: ConfigPatch): Promise<void>;

  /** 原生目录选择器（ui-rules 项目目录；浏览器/mock 环境返回 null） */
  pickDir(): Promise<string | null>;

  /**
   * 通知订阅（决策 #3 A）：注册帧回调，返回退订函数。
   * - tauri：建立守护进程推送流（`subscribe` 命令；解锁后自动重订阅）；
   * - mock：仅登记回调（模拟帧经 QA 钩子 `simulateAuthzRequest` 触发）。
   */
  subscribeNotifications(onFrame: (frame: NotificationFrame) => void): Promise<() => void>;
}
