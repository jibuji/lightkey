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

/* ---------- 规则 / 审计 / 设置 / 同步（M2） ---------- */

/** 规则（`rule.list` 结果；决策 #6：含 `name`；字段对齐 lk-core model::Rule）。 */
export interface AuthRule {
  id: string;
  /** 规范化绝对路径（守护进程侧 canonicalize）。 */
  projectDir: string;
  name: string;
  /** 具名命令（可 glob）；read 规则（M2.9 值披露）为空串。 */
  command: string;
  /** 授权注入的 key 名（最小集合）；read 规则语义为可读条目名。 */
  keys: string[];
  /** 规则能力类型（M2.9 值披露）：inject | read；旧守护进程缺省。 */
  capability?: string;
  /** 创建时间（ISO-8601 UTC）。 */
  created: string;
}

/** 新建规则输入（`rule.add`；id/created 由守护进程注入）。 */
export interface RuleInput {
  projectDir: string;
  name: string;
  command: string;
  keys: string[];
  /** 规则能力类型（M2.9 值披露）：inject（注入，缺省）| read（读值，
   *  read 规则 command 恒为空串、keys=可读条目名）。 */
  capability?: "inject" | "read";
}

export type AuditResult = "allowed" | "denied" | "timeout";

/** 审计来源通道。 */
export type AuditChannel = "cli" | "desktop" | "approval" | "wsl-bridge";

/** 审计事件（对齐 lk-core audit::AuditEvent；无密钥值）。 */
export interface AuditEvent {
  eventId: string;
  /** ISO-8601 UTC。 */
  ts: string;
  /** 启动者进程（进程链回溯结果）。 */
  starter: string;
  /** 目标程序。 */
  target: string;
  /** 命令摘要（敏感参数已脱敏）。 */
  command: string;
  result: AuditResult;
  channel: AuditChannel;
}

/** 守护进程配置视图（`config.get`；同步凭据不经此面——走系统钥匙串）。 */
export interface ConfigView {
  autoLockMinutes: number;
  approvalTimeoutSecs: number;
  sync: { url: string; intervalSecs: number } | null;
}

/** 设置页保存补丁（`config.set`；缺省字段不修改；syncUrl 空串 = 移除同步）。 */
export interface ConfigPatch {
  autoLockMinutes?: number;
  syncUrl?: string;
  pollSecs?: number;
}

/** 设置页表单形态（含主题选择；生物识别宽限 M2 置灰预留，决策 #5 B）。 */
export interface VaultSettings {
  autoLockMin: string;
  bioGrace: boolean;
  syncUrl: string;
  pollSec: string;
  retention: string;
  theme: "dark" | "light";
}

/** 最近一轮同步状态（`sync.poll` 结果映射；UI 只需上次同步时间戳）。 */
export interface SyncStatus {
  /** 上次成功同步时间戳（ISO-8601 UTC；尚未有轮次 = null）。 */
  lastSync: string | null;
}

export type PageId = "items" | "rules" | "settings" | "audit";
