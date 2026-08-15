//! 本地 IPC 协议（规格：`docs/ipc.md`）。
//!
//! - 协议：**JSON-RPC 2.0**（`jsonrpc`/`method`/`params`/`id`/`result`/`error`），
//!   serde 序列化；版本前缀方法名（`vault.unlock`、`item.get`…）。
//! - 方法表见模块内常量；M1 已实现 `sync.trigger` / `sync.poll`；M2 方法
//!   （`authz.evaluate`/`approval.request`/`rule.*`）返回 `-32601 Method not found`
//!   （占位，不实现）。
//! - 会话令牌随每次解锁轮换；除 `vault.status`/`vault.init`/`vault.unlock` 外的
//!   请求必须携带 `token`；令牌错误/过期 → 统一 `session.invalid`（防探测）。
//! - 最小字段原则：响应只含调用方被授权的最小已解密字段。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::model::{Item, ItemDraft, ItemSummary};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 框架
// ---------------------------------------------------------------------------

/// JSON-RPC 请求。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: Value,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 响应（result 与 error 二选一）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: Value, result: Value) -> RpcResponse {
        RpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i64, message: &str, data: Option<Value>) -> RpcResponse {
        RpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

/// JSON-RPC 错误对象。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

// ---------------------------------------------------------------------------
// 错误码（应用错误统一 -320xx；-32xxx 为 JSON-RPC 标准）
// ---------------------------------------------------------------------------

pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
/// 主密码错误 / 库未初始化（统一文案，防探测）。
pub const ERR_VAULT_INVALID: i64 = -32001;
/// 会话令牌缺失/错误/过期、库未解锁（统一，防探测）。
pub const ERR_SESSION_INVALID: i64 = -32002;
/// CAS 冲突（base revision 过期）。
pub const ERR_ITEM_CONFLICT: i64 = -32003;
pub const ERR_ITEM_NOT_FOUND: i64 = -32004;
/// 超出规格限制（附件 > 50MB 等）。
pub const ERR_LIMIT: i64 = -32005;
/// `vault.unlock` 限流退避中。
pub const ERR_RATE_LIMITED: i64 = -32006;
/// 库已存在（`lk init` 未带 --force）。
pub const ERR_VAULT_EXISTS: i64 = -32007;
/// 审计 HMAC 链校验失败。
pub const ERR_AUDIT_VERIFY: i64 = -32008;
/// 同步：未配置 BYO 存储（`lk sync` 前需 `lk config sync set`）。
pub const ERR_SYNC_NOT_CONFIGURED: i64 = -32009;
/// 同步：存储端错误（网络 / 4xx / 5xx）→ 本轮放弃，下一轮重试。
pub const ERR_SYNC_STORAGE: i64 = -32010;
/// 同步：远端密文被篡改/无法解密 → 报「同步数据异常」，不自动覆盖。
pub const ERR_SYNC_ANOMALY: i64 = -32011;
/// 同步：凭据缺失/钥匙串不可用。
pub const ERR_SYNC_CREDENTIALS: i64 = -32012;

pub const MSG_VAULT_INVALID: &str = "vault.invalid";
pub const MSG_SESSION_INVALID: &str = "session.invalid";
pub const MSG_ITEM_CONFLICT: &str = "item.conflict";
pub const MSG_ITEM_NOT_FOUND: &str = "item.not_found";
pub const MSG_LIMIT: &str = "item.limit";
pub const MSG_RATE_LIMITED: &str = "rate.limited";
pub const MSG_VAULT_EXISTS: &str = "vault.exists";
pub const MSG_AUDIT_VERIFY: &str = "audit.verify_failed";
pub const MSG_METHOD_NOT_FOUND: &str = "method not found";
pub const MSG_SYNC_NOT_CONFIGURED: &str = "sync.not_configured";
pub const MSG_SYNC_STORAGE: &str = "sync.storage";
pub const MSG_SYNC_ANOMALY: &str = "sync.data_anomaly";
pub const MSG_SYNC_CREDENTIALS: &str = "sync.credentials";

// ---------------------------------------------------------------------------
// 方法名
// ---------------------------------------------------------------------------

pub const M_VAULT_STATUS: &str = "vault.status";
pub const M_VAULT_INIT: &str = "vault.init";
pub const M_VAULT_UNLOCK: &str = "vault.unlock";
pub const M_VAULT_LOCK: &str = "vault.lock";
pub const M_VAULT_RECOVER: &str = "vault.recover";
pub const M_ITEM_LIST: &str = "item.list";
pub const M_ITEM_GET: &str = "item.get";
pub const M_ITEM_PUT: &str = "item.put";
pub const M_ITEM_DELETE: &str = "item.delete";
pub const M_ITEM_EXPORT: &str = "item.export";
pub const M_AUDIT_LIST: &str = "audit.list";
pub const M_AUDIT_VERIFY: &str = "audit.verify";
// M1/M2 占位（未实现 → ERR_METHOD_NOT_FOUND）
pub const M_SYNC_TRIGGER: &str = "sync.trigger";
pub const M_SYNC_POLL: &str = "sync.poll";
pub const M_AUTHZ_EVALUATE: &str = "authz.evaluate";
pub const M_APPROVAL_REQUEST: &str = "approval.request";

// ---------------------------------------------------------------------------
// 各方法参数/结果类型（最小字段）
// ---------------------------------------------------------------------------

/// `vault.status` 结果：解锁态、版本、同步水位。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    pub unlocked: bool,
    pub version: String,
    /// 同步水位（M1 起有值；M0 恒为 null）。
    pub sync_watermark: Option<String>,
}

/// `vault.init` 参数（初始化新库：设置主密码、生成恢复码/信封）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitParams {
    pub master_password: String,
    /// 已存在库时强制重置（旧数据不可恢复，UI 明示）。
    #[serde(default)]
    pub force: bool,
}

/// `vault.init` 结果：恢复码（**仅展示一次**，不记忆）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitResult {
    pub recovery_code: String,
}

/// `vault.unlock` 参数。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockParams {
    pub master_password: String,
}

/// `vault.unlock` 结果：会话令牌（hex，随每次解锁轮换）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockResult {
    pub token: String,
}

/// `item.put` 参数：新建（无 id）或整条替换（CAS）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemPutParams {
    /// 更新时必填；新建时缺省。
    pub id: Option<Uuid>,
    pub item: ItemDraft,
    /// 乐观并发（CAS）：更新时必填，须等于存储端当前 revision。
    pub expected_revision: Option<String>,
}

/// `item.put` 结果：新 revision（完整条目，最小字段原则下含调用方所需全部字段）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemPutResult {
    pub item: Item,
}

/// `item.get` 参数。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemGetParams {
    pub id: Uuid,
}

/// `item.delete` 参数（软删除 → 墓碑）。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemDeleteParams {
    pub id: Uuid,
}

/// `item.export` 参数（file 类型整包下载，M0 单机；分块协议 M1）。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemExportParams {
    pub id: Uuid,
}

/// `item.export` 结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemExportResult {
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// 附件明文（base64）。
    pub data: String,
}

/// `audit.list` 参数。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListParams {
    /// 最近 N 条（缺省 = 全部）。
    pub limit: Option<usize>,
}

/// `audit.list` 结果。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListResult {
    pub events: Vec<crate::audit::AuditEvent>,
    /// 事件总数（含被 limit 截断部分）。
    pub total: usize,
}

/// `item.list` 结果：解密态最小索引。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemListResult {
    pub items: Vec<ItemSummary>,
}

/// `vault.recover` 参数（恢复码 + 新主密码；恢复流程见 recovery.md §3）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverParams {
    pub recovery_code: String,
    pub new_password: String,
}

/// `vault.recover` 结果：新恢复码（仅展示一次）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverResult {
    pub recovery_code: String,
}

/// `audit.verify` 结果：成功验证的事件数（含轮换链语义）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerifyResult {
    pub verified: usize,
}

/// `sync.trigger` 参数（空；触发一轮同步并阻塞至完成）。
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyncTriggerParams {}

/// `sync.poll` 结果：最近一轮已完成同步的变更摘要与水位（不触发新轮次）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncPollResult {
    pub summary: Option<crate::sync::SyncSummary>,
    /// 同步水位（最近成功轮询时间，ISO-8601 UTC）。
    pub watermark: Option<String>,
}

/// 统一「会话无效」错误响应。
pub fn session_invalid(id: Value) -> RpcResponse {
    RpcResponse::err(id, ERR_SESSION_INVALID, MSG_SESSION_INVALID, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpc_framing_roundtrip() {
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            id: Value::from(1),
            method: M_VAULT_UNLOCK.into(),
            params: serde_json::json!({ "masterPassword": "pw" }),
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        let back: RpcRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.method, M_VAULT_UNLOCK);
        assert_eq!(back.params["masterPassword"], "pw");
    }

    #[test]
    fn error_response_shapes() {
        let r = session_invalid(Value::from(7));
        assert_eq!(r.error.as_ref().unwrap().code, ERR_SESSION_INVALID);
        assert_eq!(r.error.as_ref().unwrap().message, MSG_SESSION_INVALID);
        assert!(r.result.is_none());
        let ok = RpcResponse::ok(Value::from(7), serde_json::json!({"unlocked": false}));
        assert!(ok.error.is_none());
        assert_eq!(ok.result.unwrap()["unlocked"], false);
    }

    #[test]
    fn params_deserialize_camel_case() {
        let v = serde_json::json!({
            "id": "00000000-0000-0000-0000-000000000001",
            "item": { "type": "secret", "name": "k", "value": "v", "purpose": "", "expiresAt": null },
            "expectedRevision": "2026-08-15T00:00:00.000000Z"
        });
        let p: ItemPutParams = serde_json::from_value(v).unwrap();
        assert_eq!(p.id, Some(Uuid::from_u128(1)));
        assert_eq!(p.item.kind(), crate::model::ItemKind::Secret);
        assert_eq!(
            p.expected_revision.as_deref(),
            Some("2026-08-15T00:00:00.000000Z")
        );
    }
}
