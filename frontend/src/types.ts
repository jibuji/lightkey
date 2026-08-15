/**
 * LightKey 前端领域类型（与 docs/ipc.md 最小字段语义、docs/design/spec.md §4
 * 存储类型定案 v2 对应）。
 *
 * 条目类型（四类）：login / note(Markdown) / secret / file。
 * 所有条目一律真加密存储（零知识）；前端只见解密后的最小字段。
 */

export type ItemType = "login" | "note" | "secret" | "file";

export interface CustomField {
  name: string;
  value: string;
  hidden: boolean;
}

export interface BaseItem {
  id: string;
  name: string;
  /** ISO-8601 revision（CAS 依据，参考 data-model.md） */
  revision: string;
}

export interface LoginItem extends BaseItem {
  type: "login";
  username: string;
  password: string;
  uris: string[];
  custom: CustomField[];
}

export interface NoteItem extends BaseItem {
  type: "note";
  content: string;
}

export interface SecretItem extends BaseItem {
  type: "secret";
  value: string;
  purpose: string;
  /** 可选过期时间 "YYYY-MM-DD"；空串 = 无过期 */
  expiresAt: string;
}

export interface FileItem extends BaseItem {
  type: "file";
  note: string;
  /** 人类可读大小（如 "12.4 MB"） */
  size: string;
  fileType: string;
  /** 附件文件名 */
  attachment: string;
}

export type Item = LoginItem | NoteItem | SecretItem | FileItem;

/** 新建/编辑表单产出：除 id/revision 外的全部字段 */
export type ItemDraft = Omit<Item, "id" | "revision">;

/** item.list 返回的最小索引字段（ipc.md §4） */
export interface ItemSummary {
  id: string;
  name: string;
  type: ItemType;
  revision: string;
}

/* ---------- 规则 / 审计 / 设置 / 同步（M2 页骨架用 mock 数据） ---------- */

export interface AuthRule {
  id: string;
  projectDir: string;
  command: string;
  keys: string[];
  created: string;
}

export type AuditResult = "allowed" | "denied" | "timeout";

export interface AuditEvent {
  ts: string;
  starter: string;
  target: string;
  dir: string;
  result: AuditResult;
  note: string;
}

export interface VaultSettings {
  autoLockMin: string;
  bioGrace: boolean;
  syncUrl: string;
  pollSec: string;
  retention: string;
}

export interface SyncStatus {
  /** true = 已同步到最新水位 */
  synced: boolean;
  pollSec: number;
  lastSync?: string;
}

export type PageId = "items" | "rules" | "settings" | "audit";
