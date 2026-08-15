/**
 * IPC 接口层 —— LightKey 前端与本地守护进程（lk daemon）的 JSON-RPC 2.0
 * 协议面（docs/ipc.md）。本层只声明协议形状，不实现传输。
 *
 * 方法名对照 docs/ipc.md §4：
 *   status   → vault.status        unlock → vault.unlock        lock → vault.lock
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

import type { Item, ItemDraft, ItemSummary, SyncStatus } from "../types";

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

export interface UpdateOptions {
  /** 乐观并发（CAS）：传该条目加载时的 revision，不匹配则抛 ConflictError */
  expectedRevision?: string;
}

export interface LightKeyIpc {
  /** vault.status：解锁态、同步水位 */
  status(): Promise<{ unlocked: boolean }>;
  /** vault.unlock：主密码解锁；错误统一为 VaultInvalidError */
  unlock(masterPassword: string): Promise<void>;
  /** vault.lock：立即锁定（内存密钥擦除） */
  lock(): Promise<void>;

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

  /** audit.list（M2 页骨架） */
  auditList(): Promise<import("../types").AuditEvent[]>;

  /** rule.*（M2 页骨架） */
  ruleList(): Promise<import("../types").AuthRule[]>;
  ruleCreate(rule: import("../types").AuthRule): Promise<void>;
  ruleRemove(id: string): Promise<void>;
}
