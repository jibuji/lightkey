/**
 * 协议契约（protocol contract）——Rust 权威源 `crates/lk-core/src/ipc.rs` 的
 * TypeScript 镜像。
 *
 * 本文件是 D 层唯一承认的线协议事实来源：RPC 方法名 / 通知帧名 / 字符串
 * 错误码 / 审计通道值 / 审批类型。所有适配器（tauriAdapter / mockAdapter /
 * ipc-bridge）一律从这里取常量，不再手写字面量。
 *
 * 双向对齐由 `src/__tests__/protocolContract.test.ts` 钉死（解析 ipc.rs 的
 * `pub const *: &str` 常量与 authz.rs 的 `ApprovalKind` 枚举，断言与本文件
 * 逐值相等、无缺无多）——协议漂移在 CI 失败，而不是在用户端显示空列表或
 * 错配（issue #85 / #86 类事故）。
 *
 * 键名与 Rust 常量名一一镜像（`M_VAULT_STATUS` → `METHODS.VAULT_STATUS`、
 * `MSG_ITEM_CONFLICT` → `ERROR_CODES.ITEM_CONFLICT` …），便于核对。
 */

/** RPC 方法名（`lk_core::ipc::M_*`）。 */
export const METHODS = {
  VAULT_STATUS: "vault.status",
  VAULT_INIT: "vault.init",
  VAULT_UNLOCK: "vault.unlock",
  VAULT_LOCK: "vault.lock",
  VAULT_RECOVER: "vault.recover",
  ITEM_LIST: "item.list",
  ITEM_GET: "item.get",
  ITEM_PUT: "item.put",
  ITEM_DELETE: "item.delete",
  ITEM_EXPORT: "item.export",
  AUDIT_LIST: "audit.list",
  AUDIT_VERIFY: "audit.verify",
  SYNC_TRIGGER: "sync.trigger",
  SYNC_POLL: "sync.poll",
  AUTHZ_EVALUATE: "authz.evaluate",
  APPROVAL_RESULT: "approval.result",
  RULE_ADD: "rule.add",
  RULE_LIST: "rule.list",
  RULE_REMOVE: "rule.remove",
  SUBSCRIBE: "subscribe",
} as const;

/** 通知帧方法名（`lk_core::ipc::NOTIFY_*`；守护进程推送，无 `id`）。 */
export const NOTIFICATIONS = {
  ITEM_CHANGED: "item.changed",
  SESSION_UNLOCKED: "session.unlocked",
  SESSION_LOCKED: "session.locked",
  AUTHZ_REQUEST: "authz.request",
} as const;

/** 字符串错误码（`lk_core::ipc::MSG_*`；JSON-RPC error 的 message/code 语义）。
 *  数值码（`ERR_*`）只存在于 Rust 侧，不入本镜像。 */
export const ERROR_CODES = {
  CHANNEL_FORBIDDEN: "channel.forbidden",
  AUTHZ_DENIED: "authz.denied",
  VAULT_INVALID: "vault.invalid",
  SESSION_INVALID: "session.invalid",
  ITEM_CONFLICT: "item.conflict",
  ITEM_NOT_FOUND: "item.not_found",
  ITEM_LIMIT: "item.limit",
  RATE_LIMITED: "rate.limited",
  VAULT_EXISTS: "vault.exists",
  WEAK_PASSWORD: "vault.weak_password",
  AUDIT_VERIFY: "audit.verify_failed",
  METHOD_NOT_FOUND: "method not found",
  SYNC_NOT_CONFIGURED: "sync.not_configured",
  SYNC_STORAGE: "sync.storage",
  SYNC_ANOMALY: "sync.data_anomaly",
  SYNC_CREDENTIALS: "sync.credentials",
} as const;

/** 审计通道值（`lk_core::ipc::CHANNEL_*`；请求 `channel` 参数）。 */
export const CHANNELS = {
  CLI: "cli",
  WSL_BRIDGE: "wsl-bridge",
  DESKTOP: "desktop",
} as const;

/**
 * 审批类型（`lk_core::authz::ApprovalKind` serde `rename_all = "lowercase"`
 * 序列化值；`authz.request` 帧的 `kind` 字段）。值披露（M2.9，`read` /
 * `export`）+ 规则管理门（补充拍板 #22，`rule`）+ 写入门（补充拍板 #24 /
 * M2.97，`write`——单一 kind + `command` 字段承载动作
 * `item.put <name>` / `item.delete <name>`，keys = 单元素 [目标条目名]，
 * write-gate.md §6）。加性演进不升协议版本；双向对齐由
 * `protocolContract.test.ts` 解析 authz.rs 枚举钉死。
 */
export const APPROVAL_KINDS = {
  INJECT: "inject",
  READ: "read",
  EXPORT: "export",
  RULE: "rule",
  WRITE: "write",
} as const;

/**
 * 携带 `channel` 参数的方法（`lk_core::ipc::CHANNEL_BEARING_METHODS`）：
 * 授权门 + 规则 + 值披露裁决。CLI（钉 "cli" / 桥覆写 "wsl-bridge"）与
 * 桌面（钉 "desktop"）据此标注来源，清单在此与 Rust 侧共享。
 */
export const CHANNEL_BEARING_METHODS: readonly string[] = [
  METHODS.AUTHZ_EVALUATE,
  METHODS.RULE_ADD,
  METHODS.RULE_LIST,
  METHODS.RULE_REMOVE,
  METHODS.ITEM_GET,
  METHODS.ITEM_EXPORT,
];

export type Channel = (typeof CHANNELS)[keyof typeof CHANNELS];
