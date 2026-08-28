/**
 * D 层事件总线契约（`docs/plugin-architecture.md` §5.2）。
 *
 * 通过模块增强把事件挂到 Cordis `Context[Context.events]`（与
 * `@cordisjs/plugin-loader` 对 `Events` 的增强方式一致）：
 *
 * | 事件 | 负载（最小字段，无密钥值） | 起点 | 监听者 |
 * |------|--------------------------|------|--------|
 * | `item.changed` | `{ itemId, revisionDate, type, deleted }` | Rust vault-store → IPC 通知 → 本层重新 emit（mock 由 ipc-bridge 模拟） | sync 推送 · audit 记录 · ui 刷新（三方响应） |
 * | `session.unlocked` | `{ via }` | Rust session → IPC 通知 → 本层重新 emit | ui 各插件（切解锁态）· sync-engine（恢复轮询） |
 * | `session.locked` | `{ reason }` | Rust session → IPC 通知 → 本层重新 emit | ui 各插件（回解锁页）· sync-engine（暂停轮询） |
 * | `theme.changed` | `{ theme }` | theme 插件（TS 内 emit，不跨进程） | 所有 ui 插件（重渲染） |
 * | `clipboard.copied` | `{ source, field, clearedAt }` | ui 组件（TS 内 emit，不跨进程） | Toast（提示）· 30s 清除计时 |
 * | `authz.request` | `{ requestId, starter, projectDir, command, keys[], challenge }` | Rust authz-gate → IPC 通知（仅桌面订阅者可见） | approval 弹窗（**M2 已接入**） |
 * | `vault.search` | `{ query }` | topbar 搜索框（TS 内 emit，300ms 防抖） | ui-vault（过滤列表） |
 * | `vault.search-enter` | `{ query }` | topbar 搜索框回车（TS 内 emit） | ui-vault（空态引导新建） |
 * | `vault.initialized` | `{ initialized }` | ipc-bridge（守护进程 `vault.status` 探测结果，TS 内 emit，不跨进程） | 宿主（锁态整页互斥门控：无库→onboarding / 有库→unlock） |
 *
 * 分发语义：`emit`（观察广播，fire-and-forget）；`authz.request` 的审批结果
 * 经 IPC 方法 `approval.result` 回传（跨进程无同步事件返回值，§5.3）。
 */

import type { Context } from "@cordisjs/core";

/** 主题名（design/spec.md §2 的暗/浅两套 tokens）。 */
export type ThemeName = "dark" | "light";

/** `item.changed` 负载，与 Rust `VaultEvent::ItemChanged` 语义对齐（字段名映射：
 *  Rust `item_id`/`revision_date`/`kind` → 协议 `itemId`/`revisionDate`/`type`；
 *  `kind` 即 `type`，`type` 是 Rust 关键字，故 Rust 内部用 `kind`）。 */
export interface ItemChangedPayload {
  itemId: string;
  /** 新 revision（ISO-8601 UTC）。 */
  revisionDate: string;
  /** 条目类型：login / note / secret / file。 */
  type: string;
  /** 软删除（墓碑）标记。 */
  deleted: boolean;
}

/** `session.unlocked` 负载。 */
export interface SessionUnlockedPayload {
  via: "password" | "biometric" | "recovery";
}

/** `session.locked` 负载。 */
export interface SessionLockedPayload {
  reason: "manual" | "timeout" | "lockscreen" | "daemon-exit";
}

/** `clipboard.copied` 负载：`clearedAt` = 30s 清除时刻（ISO-8601）。 */
export interface ClipboardCopiedPayload {
  /** 来源（如条目 id / key 名）。 */
  source: string;
  /** 字段（如 password / username）。 */
  field: string;
  /** 30 秒后自动清除的时刻。 */
  clearedAt: string;
}

/** `authz.request` 负载（M2 已随 authz-gate + 通知桥接入）。 */
export interface AuthzRequestPayload {
  requestId: string;
  starter: string;
  projectDir: string;
  command: string;
  /** 仅 key 名，密钥值永不进事件负载。 */
  keys: string[];
  /** 一次性审批挑战（#78）：回传 `approval.result` 时必须原样带回；
   *  该值仅经桌面通知通道下发（socket 订阅者不可见）。 */
  challenge: string;
  /** 锁定态一体化（#67）：弹窗须同时收集主密码（临时解锁 + 本次授权
   *  一次交互），允许决策回传 `masterPassword`；守护进程临时解锁后
   *  不签发会话令牌——本次注入不产生 item.* 全量能力（#65）。 */
  needsUnlock: boolean;
  /** 审批类型（M2.9 值披露）：弹窗按 kind 选形态；缺省视为 inject。 */
  kind?: "inject" | "read" | "export";
  /** export 审批的数据包规模元信息（仅 kind=export；不含数据本身）。 */
  exportMeta?: { name: string; mime: string; size: number } | null;
}

/** `vault.search` 负载（topbar 搜索框 → ui-vault；300ms 防抖）。 */
export interface VaultSearchPayload {
  query: string;
}

declare module "@cordisjs/core" {
  interface Events {
    "item.changed"(payload: ItemChangedPayload): void;
    "session.unlocked"(payload: SessionUnlockedPayload): void;
    "session.locked"(payload: SessionLockedPayload): void;
    "theme.changed"(payload: { theme: ThemeName }): void;
    "clipboard.copied"(payload: ClipboardCopiedPayload): void;
    "authz.request"(payload: AuthzRequestPayload): void;
    /** topbar 搜索词（防抖后）。 */
    "vault.search"(payload: VaultSearchPayload): void;
    /** topbar 搜索框回车（空态「未找到，按回车新建」引导）。 */
    "vault.search-enter"(payload: VaultSearchPayload): void;
    /** 首启门控：守护进程库状态探测结果（ipc-bridge 本地 emit；宿主据
     *  此在初始化向导与解锁页间互斥切换，M2.5）。 */
    "vault.initialized"(payload: { initialized: boolean }): void;
  }
}

export type LightKeyEvents = Context["events"];

/** 剪贴板 30s 自动清除（D12 / design/spec.md §6.3 同款行为）。 */
export const CLIPBOARD_CLEAR_MS = 30_000;
