//! lk-cli 专用 typed IPC client（JSON-RPC 深模块）。
//!
//! 把「方法名 / 参数形状 / 响应解析 / 错误码语义」这份协议知识收进一处：
//! `cmd_*` 只做呈现与交互编排，不再手搓 `serde_json::Value`。lk-daemon /
//! lk-core 不在此列——全仓 Rust 侧只有 lk-cli 一个 JSON-RPC 消费者，不造
//! 假设性复用面。
//!
//! 设计要点：
//! - **可测试 seam**：[`RpcClient`] 泛型注入 transport
//!   （`FnMut(&str, Value) -> Result<Value, RpcError>`）；生产路径由
//!   main.rs 的薄适配（local UDS / bridge 子进程分流 + 会话令牌注入）提供，
//!   单测注入 fake transport，不加进程级集成测试。
//! - **响应类型**：优先复用 lk-core 已有模型类型（`model::Item` /
//!   `ItemSummary` / `Rule`、`audit::AuditEvent`、`sync::SyncSummary`）；
//!   确实缺的（vault.status / audit.list / authz.evaluate 响应）在本模块
//!   定义本地 struct。缺字段兜底行为与重构前的 `unwrap_or_default` 逐点一致
//!   （行为零变化），仅 `item.get`/`item.put` 的条目体改为强类型解析。
//! - **错误语义**：服务端错误码 → [`RpcError`] 变体的分类在
//!   [`RpcError::classify`]；「变体 → 中文文案」映射留在呈现层（main.rs）。

use std::collections::BTreeMap;

use lk_core::audit::AuditEvent;
use lk_core::ipc::{
    RpcResponse, CHANNEL_CLI, ERR_AUTHZ_DENIED, ERR_CHANNEL_FORBIDDEN, ERR_ITEM_CONFLICT,
    ERR_ITEM_NOT_FOUND, ERR_LIMIT, ERR_PARSE, ERR_RATE_LIMITED, ERR_SESSION_INVALID,
    ERR_SYNC_ANOMALY, ERR_SYNC_CREDENTIALS, ERR_SYNC_NOT_CONFIGURED, ERR_SYNC_STORAGE,
    ERR_VAULT_EXISTS, ERR_VAULT_INVALID, ERR_WEAK_PASSWORD, MSG_CHANNEL_FORBIDDEN, M_AUDIT_LIST,
    M_AUDIT_VERIFY, M_AUTHZ_EVALUATE, M_ITEM_DELETE, M_ITEM_EXPORT, M_ITEM_GET, M_ITEM_LIST,
    M_ITEM_PUT, M_RULE_ADD, M_RULE_LIST, M_RULE_REMOVE, M_SYNC_TRIGGER, M_VAULT_INIT, M_VAULT_LOCK,
    M_VAULT_RECOVER, M_VAULT_STATUS, M_VAULT_UNLOCK,
};
use lk_core::model::{Item, ItemDraft, ItemSummary, Rule};
use lk_core::sync::SyncSummary;
use serde_json::{json, Value};

use crate::bridge::{ERR_BRIDGE_IO, ERR_BRIDGE_NO_DAEMON, ERR_BRIDGE_VERSION_INCOMPATIBLE};

// ---------------------------------------------------------------------------
// 错误语义
// ---------------------------------------------------------------------------

/// RPC 失败的统一错误类型（承载错误码语义 + detail）。
///
/// - 业务错误：daemon 返回 JSON-RPC error 帧，按错误码分类为具名变体；
/// - 传输失败：连接 / 读写 / 探测分型 Fatal 等，`message` 为已格式化的
///   完整报错文案（与重构前逐字一致，由呈现层原样输出）;
/// - 响应非法：响应帧缺失 / 非 UTF-8 / 字段不符合协议约定。
#[derive(Debug, Clone)]
pub enum RpcError {
    /// 主密码错误或库未初始化（统一文案，防探测）。
    VaultInvalid,
    /// 库未解锁或会话已失效（统一，防探测）。
    SessionInvalid,
    /// 值披露裁决拒绝（M2.9：读/导出未命中规则且未批准/超时/无 UI；
    /// 统一不区分原因防探测，spec value-disclosure §5.4/§7）。
    AuthzDenied,
    /// CAS 冲突（base revision 过期）。
    ItemConflict,
    ItemNotFound,
    Limit {
        detail: String,
    },
    RateLimited {
        retry_after_seconds: u64,
    },
    VaultExists,
    WeakPassword,
    SyncNotConfigured {
        detail: String,
    },
    SyncStorage {
        detail: String,
    },
    SyncAnomaly {
        detail: String,
    },
    SyncCredentials {
        detail: String,
    },
    BridgeNoDaemon {
        detail: String,
    },
    BridgeVersionIncompatible {
        detail: String,
    },
    BridgeIo {
        detail: String,
    },
    /// socket/pipe 通道提交了只允许桌面内嵌直调的方法（如 `approval.result`）
    /// 被拒（-32014，与 bridge 的 `bridge.no_daemon` 撞码，按错误帧 message
    /// 消歧，issue #103）。
    ChannelForbidden,
    /// 未归类的服务端业务错误（保留原始 message/detail 与数字码——`--json`
    /// 失败对象里 error 名归 `other`、code 兜底保留原始值，issue #103）。
    Other {
        code: i64,
        message: String,
        detail: String,
    },
    /// 传输层失败（连接失败、bridge 启动/读写失败等）。
    Transport {
        message: String,
    },
    /// 响应帧缺失/非法，或响应字段不符合协议约定。
    BadResponse {
        message: String,
    },
}

impl RpcError {
    /// 服务端 JSON-RPC error 对象 → 具语义变体（未知码归入 [`RpcError::Other`]）。
    ///
    /// -32014 撞码消歧（issue #103）：daemon 的 `channel.forbidden` 与 bridge
    /// 的 `bridge.no_daemon` 同码不同源，按错误帧 message 分型。
    pub fn classify(code: i64, message: String, data: Option<&Value>) -> RpcError {
        let detail = data
            .and_then(|d| d.get("detail"))
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        match code {
            ERR_VAULT_INVALID => RpcError::VaultInvalid,
            ERR_SESSION_INVALID => RpcError::SessionInvalid,
            ERR_AUTHZ_DENIED => RpcError::AuthzDenied,
            ERR_ITEM_CONFLICT => RpcError::ItemConflict,
            ERR_ITEM_NOT_FOUND => RpcError::ItemNotFound,
            ERR_LIMIT => RpcError::Limit { detail },
            ERR_RATE_LIMITED => RpcError::RateLimited {
                retry_after_seconds: data
                    .and_then(|d| d.get("retryAfterSeconds"))
                    .and_then(|d| d.as_u64())
                    .unwrap_or(0),
            },
            ERR_VAULT_EXISTS => RpcError::VaultExists,
            ERR_WEAK_PASSWORD => RpcError::WeakPassword,
            ERR_SYNC_NOT_CONFIGURED => RpcError::SyncNotConfigured { detail },
            ERR_SYNC_STORAGE => RpcError::SyncStorage { detail },
            ERR_SYNC_ANOMALY => RpcError::SyncAnomaly { detail },
            ERR_SYNC_CREDENTIALS => RpcError::SyncCredentials { detail },
            // -32014 双义（issue #103）：daemon 帧 message=channel.forbidden；
            // 其余（bridge 帧 message=bridge.no_daemon）维持 bridge 语义。
            ERR_BRIDGE_NO_DAEMON if message == MSG_CHANNEL_FORBIDDEN => RpcError::ChannelForbidden,
            ERR_BRIDGE_NO_DAEMON => RpcError::BridgeNoDaemon { detail },
            ERR_BRIDGE_VERSION_INCOMPATIBLE => RpcError::BridgeVersionIncompatible { detail },
            ERR_BRIDGE_IO => RpcError::BridgeIo { detail },
            _ => RpcError::Other {
                code,
                message,
                detail,
            },
        }
    }

    /// `--json` 失败对象的机器可读契约（docs/agent-cli.md）：返回
    /// （error 名, code）。error 名在 CLI 内唯一——同码不同源已由
    /// [`RpcError::classify`] 消歧为不同变体；`code` 只作兜底键，CLI 本地
    /// 失败（transport / bad_response）无服务端错误码，固定 0。
    pub fn machine(&self) -> (&'static str, i64) {
        match self {
            RpcError::VaultInvalid => ("vault.invalid", ERR_VAULT_INVALID),
            RpcError::SessionInvalid => ("session.invalid", ERR_SESSION_INVALID),
            RpcError::AuthzDenied => ("authz.denied", ERR_AUTHZ_DENIED),
            RpcError::ItemConflict => ("item.conflict", ERR_ITEM_CONFLICT),
            RpcError::ItemNotFound => ("item.not_found", ERR_ITEM_NOT_FOUND),
            RpcError::Limit { .. } => ("item.limit", ERR_LIMIT),
            RpcError::RateLimited { .. } => ("rate.limited", ERR_RATE_LIMITED),
            RpcError::VaultExists => ("vault.exists", ERR_VAULT_EXISTS),
            RpcError::WeakPassword => ("vault.weak_password", ERR_WEAK_PASSWORD),
            RpcError::SyncNotConfigured { .. } => ("sync.not_configured", ERR_SYNC_NOT_CONFIGURED),
            RpcError::SyncStorage { .. } => ("sync.storage", ERR_SYNC_STORAGE),
            RpcError::SyncAnomaly { .. } => ("sync.data_anomaly", ERR_SYNC_ANOMALY),
            RpcError::SyncCredentials { .. } => ("sync.credentials", ERR_SYNC_CREDENTIALS),
            RpcError::ChannelForbidden => ("channel.forbidden", ERR_CHANNEL_FORBIDDEN),
            RpcError::BridgeNoDaemon { .. } => ("bridge.no_daemon", ERR_BRIDGE_NO_DAEMON),
            RpcError::BridgeVersionIncompatible { .. } => (
                "bridge.version_incompatible",
                ERR_BRIDGE_VERSION_INCOMPATIBLE,
            ),
            RpcError::BridgeIo { .. } => ("bridge.io", ERR_BRIDGE_IO),
            RpcError::Other { code, .. } => ("other", *code),
            RpcError::Transport { .. } => ("transport", 0),
            RpcError::BadResponse { .. } => ("bad_response", 0),
        }
    }
}

// ---------------------------------------------------------------------------
// 可注入传输 seam
// ---------------------------------------------------------------------------

/// typed 客户端：泛型注入 transport（method + params → result 或错误）。
pub struct RpcClient<F> {
    transport: F,
}

impl<F> RpcClient<F>
where
    F: FnMut(&str, Value) -> Result<Value, RpcError>,
{
    pub fn new(transport: F) -> Self {
        RpcClient { transport }
    }

    /// 发送一帧并返回原始 result（各 typed 方法的唯一出口）。
    fn call(&mut self, method: &str, params: Value) -> Result<Value, RpcError> {
        (self.transport)(method, params)
    }
}

// ---------------------------------------------------------------------------
// 本地响应 struct（lk-core 无对应模型类型）
// ---------------------------------------------------------------------------

/// `vault.status` 响应（CLI 只消费 unlocked / version / syncWatermark）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultStatus {
    pub unlocked: bool,
    pub version: String,
    pub sync_watermark: Option<String>,
}

/// `audit.list` 响应页。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditPage {
    pub events: Vec<AuditEvent>,
    pub total: u64,
}

/// `audit.verify` 结果（含锚点交叉核对；`truncated` = 截断检测，调用方据此退出非零）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerifyOutcome {
    pub verified: u64,
    pub anchor_ok: bool,
    pub anchor_degraded: bool,
    pub truncated: bool,
    pub chain_ordinal: u64,
    pub anchor_ordinal: Option<u64>,
}

/// `authz.evaluate` 裁决结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzDecision {
    pub allowed: bool,
    pub reason: String,
    /// 只含被授权 key 的 env（值在此刻才离开守护进程）。
    pub env: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// 解析辅助（缺字段兜底 = 重构前 unwrap_or_default 行为）
// ---------------------------------------------------------------------------

/// 解析响应里的强类型条目体（item.get / item.put 的 `item` 字段或整体）。
fn parse_item(value: Value) -> Result<Item, RpcError> {
    serde_json::from_value::<Item>(value).map_err(|e| RpcError::BadResponse {
        message: format!("条目响应解析失败：{e}"),
    })
}

/// 解析单行 JSON-RPC 响应 → result / 已分类错误（local 与 bridge 共用）。
pub fn parse_response_line(line: &str) -> Result<Value, RpcError> {
    let resp: RpcResponse = serde_json::from_str(line).unwrap_or(RpcResponse {
        jsonrpc: "2.0".into(),
        id: Value::Null,
        result: None,
        error: Some(lk_core::ipc::RpcError {
            code: ERR_PARSE,
            message: "响应解析失败".into(),
            data: None,
        }),
    });
    match (resp.result, resp.error) {
        (Some(result), _) => Ok(result),
        (None, Some(err)) => Err(RpcError::classify(err.code, err.message, err.data.as_ref())),
        (None, None) => Err(RpcError::BadResponse {
            message: "空响应".to_string(),
        }),
    }
}

// ---------------------------------------------------------------------------
// typed 方法：库生命周期
// ---------------------------------------------------------------------------

impl<F: FnMut(&str, Value) -> Result<Value, RpcError>> RpcClient<F> {
    /// `vault.init` → 新恢复码（缺失兜底空串，同重构前）。
    pub fn vault_init(&mut self, master_password: &str, force: bool) -> Result<String, RpcError> {
        let res = self.call(
            M_VAULT_INIT,
            json!({ "masterPassword": master_password, "force": force }),
        )?;
        Ok(res["recoveryCode"].as_str().unwrap_or_default().to_string())
    }

    /// `vault.unlock`。
    pub fn vault_unlock(&mut self, master_password: &str) -> Result<(), RpcError> {
        self.call(M_VAULT_UNLOCK, json!({ "masterPassword": master_password }))?;
        Ok(())
    }

    /// `vault.lock`。
    pub fn vault_lock(&mut self) -> Result<(), RpcError> {
        self.call(M_VAULT_LOCK, json!({}))?;
        Ok(())
    }

    /// `vault.status`。
    pub fn vault_status(&mut self) -> Result<VaultStatus, RpcError> {
        let res = self.call(M_VAULT_STATUS, json!({}))?;
        Ok(VaultStatus {
            unlocked: res["unlocked"].as_bool().unwrap_or(false),
            version: res["version"].as_str().unwrap_or_default().to_string(),
            sync_watermark: res["syncWatermark"].as_str().map(str::to_string),
        })
    }

    /// `vault.recover` → 新恢复码（缺失兜底空串，同重构前）。
    pub fn vault_recover(
        &mut self,
        recovery_code: &str,
        new_password: &str,
    ) -> Result<String, RpcError> {
        let res = self.call(
            M_VAULT_RECOVER,
            json!({ "recoveryCode": recovery_code, "newPassword": new_password }),
        )?;
        Ok(res["recoveryCode"].as_str().unwrap_or_default().to_string())
    }

    // -----------------------------------------------------------------------
    // 条目
    // -----------------------------------------------------------------------

    /// `item.list` → 最小字段摘要（解析失败兜底空列表，同重构前）。
    pub fn item_list(&mut self) -> Result<Vec<ItemSummary>, RpcError> {
        let res = self.call(M_ITEM_LIST, json!({}))?;
        Ok(serde_json::from_value(res["items"].clone()).unwrap_or_default())
    }

    /// `item.get` → 完整解密条目（强类型解析）。
    pub fn item_get(&mut self, id: &str) -> Result<Item, RpcError> {
        let res = self.call(M_ITEM_GET, json!({ "id": id }))?;
        parse_item(res)
    }

    /// `item.put`（新建）→ 落库后的完整条目。
    pub fn item_put(&mut self, draft: &ItemDraft) -> Result<Item, RpcError> {
        let res = self.call(M_ITEM_PUT, json!({ "item": draft }))?;
        parse_item(res["item"].clone())
    }

    /// `item.put`（CAS 编辑）→ 落库后的完整条目。
    pub fn item_update(
        &mut self,
        id: &str,
        draft: &ItemDraft,
        expected_revision: &str,
    ) -> Result<Item, RpcError> {
        let res = self.call(
            M_ITEM_PUT,
            json!({
                "id": id,
                "item": draft,
                "expectedRevision": expected_revision,
            }),
        )?;
        parse_item(res["item"].clone())
    }

    /// `item.delete`（软删除，墓碑）。
    pub fn item_delete(&mut self, id: &str) -> Result<(), RpcError> {
        self.call(M_ITEM_DELETE, json!({ "id": id }))?;
        Ok(())
    }

    /// `item.export` → 附件字节（base64 解码属协议知识，收在本模块）。
    pub fn item_export(&mut self, id: &str) -> Result<Vec<u8>, RpcError> {
        let res = self.call(M_ITEM_EXPORT, json!({ "id": id }))?;
        use base64::Engine as _;
        match res["data"].as_str() {
            Some(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| RpcError::BadResponse {
                    message: format!("附件数据解码失败：{e}"),
                }),
            None => Err(RpcError::BadResponse {
                message: "附件数据缺失".to_string(),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // 审计
    // -----------------------------------------------------------------------

    /// `audit.list`（只读；无密钥值）。
    pub fn audit_list(&mut self, limit: Option<usize>) -> Result<AuditPage, RpcError> {
        let res = self.call(M_AUDIT_LIST, json!({ "limit": limit }))?;
        Ok(AuditPage {
            events: serde_json::from_value(res["events"].clone()).unwrap_or_default(),
            total: res["total"].as_u64().unwrap_or(0),
        })
    }

    /// `audit.verify` → 校验通过的事件数 + 锚点交叉核对结果（截断检测）。
    pub fn audit_verify(&mut self) -> Result<AuditVerifyOutcome, RpcError> {
        let res = self.call(M_AUDIT_VERIFY, json!({}))?;
        Ok(AuditVerifyOutcome {
            verified: res["verified"].as_u64().unwrap_or(0),
            anchor_ok: res["anchorOk"].as_bool().unwrap_or(false),
            anchor_degraded: res["anchorDegraded"].as_bool().unwrap_or(false),
            truncated: res["truncated"].as_bool().unwrap_or(false),
            chain_ordinal: res["chainOrdinal"].as_u64().unwrap_or(0),
            anchor_ordinal: res["anchorOrdinal"].as_u64(),
        })
    }

    // -----------------------------------------------------------------------
    // 同步
    // -----------------------------------------------------------------------

    /// `sync.trigger` → 一轮同步摘要。
    pub fn sync_trigger(&mut self) -> Result<SyncSummary, RpcError> {
        let res = self.call(M_SYNC_TRIGGER, json!({}))?;
        Ok(serde_json::from_value(res).unwrap_or_default())
    }

    // -----------------------------------------------------------------------
    // 授权门（规则管理 / 注入）
    // -----------------------------------------------------------------------

    /// `rule.add` → 入库规则。daemon 返回的 rule 体无法解析时兜底合成
    /// （nil id + 请求参数回填），与重构前行为逐字一致。
    /// `capability`：`Some("read")` = 读值规则（M2.9，`--read`）、
    /// `Some("write")` = 写规则（M2.97，`--write`）；`None` = 注入规则
    /// （不带 capability 字段，老守护进程兼容）。`actions` 仅写规则携带
    /// （write-gate.md §7 加性字段）；daemon 返回的 rule 体无法解析时兜底
    /// 合成（nil id + 请求参数回填），与重构前行为逐字一致。
    pub fn rule_add(
        &mut self,
        project_dir: &str,
        name: &str,
        command: &str,
        keys: &[String],
        capability: Option<&str>,
        actions: Option<&[String]>,
    ) -> Result<Rule, RpcError> {
        let mut params = json!({
            "projectDir": project_dir,
            "name": name,
            "command": command,
            "keys": keys,
            "channel": CHANNEL_CLI,
        });
        if let Some(cap) = capability {
            params["capability"] = json!(cap);
        }
        if let Some(actions) = actions {
            params["actions"] = json!(actions);
        }
        let res = self.call(M_RULE_ADD, params)?;
        let fallback = Rule {
            id: uuid::Uuid::nil(),
            project_dir: project_dir.to_string(),
            name: name.to_string(),
            command: command.to_string(),
            keys: keys.to_vec(),
            capability: capability
                .unwrap_or(lk_core::model::RULE_CAPABILITY_INJECT)
                .into(),
            actions: actions
                .map(<[String]>::to_vec)
                .unwrap_or_else(lk_core::model::default_rule_actions),
            fingerprint: None,
            created: String::new(),
        };
        Ok(serde_json::from_value(res["rule"].clone()).unwrap_or(fallback))
    }

    /// `rule.list` → 规则列表（解析失败兜底空列表，同重构前）。
    pub fn rule_list(&mut self) -> Result<Vec<Rule>, RpcError> {
        let res = self.call(M_RULE_LIST, json!({ "channel": CHANNEL_CLI }))?;
        Ok(serde_json::from_value(res["rules"].clone()).unwrap_or_default())
    }

    /// `rule.remove`（软删除，墓碑）。
    pub fn rule_remove(&mut self, id: &str) -> Result<(), RpcError> {
        self.call(M_RULE_REMOVE, json!({ "id": id, "channel": CHANNEL_CLI }))?;
        Ok(())
    }

    /// `authz.evaluate` → 三层授权裁决（不传 starter/cwd：守护进程以 IPC
    /// 对端真实 PID 回溯 + 真实 cwd 判定）。
    pub fn authz_evaluate(
        &mut self,
        command: &str,
        keys: &[String],
    ) -> Result<AuthzDecision, RpcError> {
        let res = self.call(
            M_AUTHZ_EVALUATE,
            json!({ "command": command, "keys": keys, "channel": CHANNEL_CLI }),
        )?;
        Ok(AuthzDecision {
            allowed: res["allowed"].as_bool().unwrap_or(false),
            reason: res["reason"].as_str().unwrap_or("denied").to_string(),
            env: serde_json::from_value(res["env"].clone()).unwrap_or_default(),
        })
    }
}

// ---------------------------------------------------------------------------
// 测试（fake transport 钉死参数形状 / 响应解析 / 错误分类）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 记录调用（method + params）的 fake transport 载体。
    #[derive(Default, Clone)]
    struct Recorder {
        calls: std::rc::Rc<std::cell::RefCell<Vec<(String, Value)>>>,
    }

    impl Recorder {
        fn record(&self, method: &str, params: &Value) {
            self.calls
                .borrow_mut()
                .push((method.to_string(), params.clone()));
        }

        fn last(&self) -> (String, Value) {
            self.calls.borrow().last().expect("至少一次调用").clone()
        }
    }

    /// 组装成功回放固定 result 的客户端。
    fn ok_client(
        rec: &Recorder,
        result: Value,
    ) -> RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + '_> {
        let rec2 = rec.clone();
        RpcClient::new(move |method, params| {
            rec2.record(method, &params);
            Ok(result.clone())
        })
    }

    /// 组装回放 error 帧的客户端（走 classify 分类路径）。
    fn err_client<'a>(
        rec: &'a Recorder,
        code: i64,
        message: &str,
        data: Option<Value>,
    ) -> RpcClient<impl FnMut(&str, Value) -> Result<Value, RpcError> + 'a> {
        let message = message.to_string();
        let rec2 = rec.clone();
        RpcClient::new(move |method, params| {
            rec2.record(method, &params);
            Err(RpcError::classify(code, message.clone(), data.as_ref()))
        })
    }

    const LOGIN_JSON: &str = r#"{
        "type": "login", "id": "00000000-0000-0000-0000-000000000001",
        "name": "示例", "revision": "rev-1", "deleted": false,
        "username": "u", "password": "p",
        "uris": ["https://a"], "custom": [{"name": "k", "value": "v", "hidden": true}]
    }"#;

    // ------------------------- 参数形状钉死 -------------------------

    /// vault.init 参数形状：masterPassword + force，方法名钉死。
    #[test]
    fn vault_init_params_shape() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "recoveryCode": "ABCD-EFGH" }));
        let code = c.vault_init("pw123", false).unwrap();
        assert_eq!(rec.last().0, "vault.init");
        assert_eq!(
            rec.last().1,
            json!({ "masterPassword": "pw123", "force": false })
        );
        assert_eq!(code, "ABCD-EFGH");
    }

    /// item.get 参数形状：{"id": …}；item.update 形状：id + item +
    /// expectedRevision（CAS 依据）。
    #[test]
    fn item_get_and_update_params_shape() {
        let rec = Recorder::default();
        let item: Value = serde_json::from_str(LOGIN_JSON).unwrap();
        // item.get 的 result 就是条目本体（不包 item 字段）
        let mut c = ok_client(&rec, item);
        c.item_get("abc").unwrap();
        assert_eq!(rec.last().0, "item.get");
        assert_eq!(rec.last().1, json!({ "id": "abc" }));

        // item.put（编辑）的 result 包在 item 字段内
        let item: Value = serde_json::from_str(LOGIN_JSON).unwrap();
        let rec2 = Recorder::default();
        let mut c2 = ok_client(&rec2, json!({ "item": item }));
        let draft = ItemDraft::Note {
            name: "n".into(),
            content: "c".into(),
        };
        c2.item_update("abc", &draft, "rev-1").unwrap();
        assert_eq!(rec2.last().0, "item.put");
        assert_eq!(
            rec2.last().1,
            json!({ "id": "abc", "item": draft, "expectedRevision": "rev-1" })
        );
    }

    /// 授权门三方法的 channel 字段钉死为 cli（bridge 覆写是传输层职责，
    /// 不在本模块）。
    #[test]
    fn gate_methods_pin_channel_cli() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "allowed": true, "reason": "", "env": {} }));
        c.rule_list().unwrap();
        assert_eq!(rec.last().1, json!({ "channel": "cli" }));
        c.authz_evaluate("npm publish", &["NPM_TOKEN".to_string()])
            .unwrap();
        assert_eq!(rec.last().0, "authz.evaluate");
        assert_eq!(
            rec.last().1,
            json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" })
        );
        c.rule_remove("r1").unwrap();
        assert_eq!(rec.last().0, "rule.remove");
        assert_eq!(rec.last().1, json!({ "id": "r1", "channel": "cli" }));
    }

    /// audit.list 的 limit 直通参数（None 序列化为 null，与重构前一致）。
    #[test]
    fn audit_list_limit_param_shape() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "events": [], "total": 0 }));
        c.audit_list(None).unwrap();
        assert_eq!(rec.last().1, json!({ "limit": null }));
        c.audit_list(Some(5)).unwrap();
        assert_eq!(rec.last().1, json!({ "limit": 5 }));
    }

    // ------------------------- 响应解析（合法 / 缺字段） -------------------------

    /// 合法 login 响应 → 强类型 Item；字段值逐一对上。
    #[test]
    fn item_get_parses_login() {
        let rec = Recorder::default();
        let item: Value = serde_json::from_str(LOGIN_JSON).unwrap();
        let mut c = ok_client(&rec, item);
        let got = c.item_get("abc").unwrap();
        match got {
            Item::Login {
                id,
                name,
                revision,
                deleted,
                username,
                password,
                uris,
                custom,
            } => {
                assert_eq!(id.to_string(), "00000000-0000-0000-0000-000000000001");
                assert_eq!(name, "示例");
                assert_eq!(revision, "rev-1");
                assert!(!deleted);
                assert_eq!(username, "u");
                assert_eq!(password, "p");
                assert_eq!(uris, vec!["https://a".to_string()]);
                assert_eq!(custom.len(), 1);
                assert!(custom[0].hidden);
            }
            _ => panic!("应为 Login 变体"),
        }
    }

    /// 缺必需字段的条目体 → BadResponse（不再静默打印空串）。
    #[test]
    fn item_get_missing_required_field_is_bad_response() {
        let rec = Recorder::default();
        let bad = json!({ "type": "login", "id": "00000000-0000-0000-0000-000000000001" });
        let mut c = ok_client(&rec, bad);
        assert!(matches!(
            c.item_get("abc"),
            Err(RpcError::BadResponse { .. })
        ));
    }

    /// vault.status 缺字段兜底：unlocked=false / version="" / watermark=None
    /// （与重构前 unwrap_or_default 一致）；合法响应逐字段解析。
    #[test]
    fn vault_status_lenient_parse() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({}));
        let st = c.vault_status().unwrap();
        assert!(!st.unlocked);
        assert_eq!(st.version, "");
        assert_eq!(st.sync_watermark, None);

        let rec = Recorder::default();
        let mut c = ok_client(
            &rec,
            json!({ "unlocked": true, "version": "0.3.0", "syncWatermark": "w-42" }),
        );
        let st = c.vault_status().unwrap();
        assert!(st.unlocked);
        assert_eq!(st.version, "0.3.0");
        assert_eq!(st.sync_watermark.as_deref(), Some("w-42"));
    }

    /// audit.list / sync.trigger / authz.evaluate 的合法与缺字段解析。
    #[test]
    fn page_summary_decision_lenient_parse() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({}));
        let page = c.audit_list(Some(3)).unwrap();
        assert!(page.events.is_empty());
        assert_eq!(page.total, 0);
        let summary = c.sync_trigger().unwrap();
        assert!(!summary.ran);
        assert_eq!(summary.pulled, 0);

        let rec = Recorder::default();
        let mut c = ok_client(
            &rec,
            json!({ "allowed": false, "reason": "timeout", "env": {"K": "v"} }),
        );
        let d = c.authz_evaluate("cmd", &[]).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.reason, "timeout");
        assert_eq!(d.env.get("K").map(String::as_str), Some("v"));

        // 缺字段兜底：allowed=false、reason="denied"、env 空（同重构前）
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({}));
        let d = c.authz_evaluate("cmd", &[]).unwrap();
        assert!(!d.allowed);
        assert_eq!(d.reason, "denied");
        assert!(d.env.is_empty());
    }

    /// item.export：base64 解码；缺失 → 「附件数据缺失」。
    #[test]
    fn item_export_decodes_base64() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "data": "aGVsbG8=" })); // "hello"
        assert_eq!(c.item_export("f1").unwrap(), b"hello");

        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({}));
        match c.item_export("f1") {
            Err(RpcError::BadResponse { message }) => assert_eq!(message, "附件数据缺失"),
            other => panic!("期望 BadResponse，得到 {other:?}"),
        }
    }

    /// rule.add：正常解析 daemon 回传 rule；异常体兜底合成（nil id + 参数回填，
    /// 与重构前 unwrap_or_else 行为一致）。
    #[test]
    fn rule_add_fallback_synthesizes_rule() {
        let rec = Recorder::default();
        let rule = json!({
            "id": "00000000-0000-0000-0000-000000000002",
            "projectDir": "/p", "name": "publish", "command": "npm publish",
            "keys": ["T"], "created": "2026-01-01T00:00:00Z"
        });
        let mut c = ok_client(&rec, json!({ "rule": rule }));
        let got = c
            .rule_add(
                "/p",
                "publish",
                "npm publish",
                &["T".to_string()],
                None,
                None,
            )
            .unwrap();
        assert_eq!(got.id.to_string(), "00000000-0000-0000-0000-000000000002");

        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({}));
        let got = c
            .rule_add(
                "/p",
                "publish",
                "npm publish",
                &["T".to_string()],
                None,
                None,
            )
            .unwrap();
        assert_eq!(got.id, uuid::Uuid::nil());
        assert_eq!(got.project_dir, "/p");
        assert_eq!(got.keys, vec!["T".to_string()]);
    }

    /// rule.add 参数形状（M2.9 值披露）：read 规则带 capability=read 且
    /// command 为空串；inject 规则省略 capability 字段（老守护进程兼容）。
    #[test]
    fn rule_add_capability_params_shape() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "rule": {} }));
        // 读规则：--read → capability=read，command 空串
        c.rule_add(
            "/p",
            "read-config",
            "",
            &["APIKey".to_string()],
            Some("read"),
            None,
        )
        .unwrap();
        assert_eq!(rec.last().0, "rule.add");
        assert_eq!(
            rec.last().1,
            json!({ "projectDir": "/p", "name": "read-config", "command": "",
                    "keys": ["APIKey"], "capability": "read", "channel": "cli" })
        );
        // 注入规则：无 capability 字段（缺省 inject，向后兼容）
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "rule": {} }));
        c.rule_add("/p", "publish", "npm *", &["T".to_string()], None, None)
            .unwrap();
        assert!(
            rec.last().1.get("capability").is_none(),
            "inject 规则不携带 capability 字段"
        );
    }

    /// rule.add 参数形状（M2.97 写门，write-gate.md §7）：write 规则带
    /// capability=write + actions 数组（加性字段）；read/inject 规则不带
    /// actions 字段。
    #[test]
    fn rule_add_write_actions_params_shape() {
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "rule": {} }));
        c.rule_add(
            "/p",
            "write-e2e",
            "",
            &["NPM_TOKEN".to_string()],
            Some("write"),
            Some(&["create".to_string(), "update".to_string()]),
        )
        .unwrap();
        assert_eq!(rec.last().0, "rule.add");
        assert_eq!(
            rec.last().1,
            json!({ "projectDir": "/p", "name": "write-e2e", "command": "",
                    "keys": ["NPM_TOKEN"], "capability": "write",
                    "actions": ["create", "update"], "channel": "cli" })
        );
        // read 规则不带 actions 字段
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "rule": {} }));
        c.rule_add("/p", "r", "", &["K".to_string()], Some("read"), None)
            .unwrap();
        assert!(
            rec.last().1.get("actions").is_none(),
            "read 规则不携带 actions"
        );
        // inject 规则不带 capability + actions 字段
        let rec = Recorder::default();
        let mut c = ok_client(&rec, json!({ "rule": {} }));
        c.rule_add("/p", "pub", "npm *", &["T".to_string()], None, None)
            .unwrap();
        assert!(
            rec.last().1.get("actions").is_none(),
            "inject 规则不携带 actions"
        );
    }

    // ------------------------- 错误分类 -------------------------

    /// 错误码 → 正确 enum 变体；限流提取 retryAfterSeconds；未知码归 Other。
    #[test]
    fn classification_maps_codes_to_variants() {
        use lk_core::ipc::{ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND};
        let cls = |code, data: Option<Value>| RpcError::classify(code, "m".into(), data.as_ref());
        assert!(matches!(
            cls(ERR_VAULT_INVALID, None),
            RpcError::VaultInvalid
        ));
        assert!(matches!(
            cls(ERR_SESSION_INVALID, None),
            RpcError::SessionInvalid
        ));
        assert!(matches!(
            cls(ERR_ITEM_CONFLICT, None),
            RpcError::ItemConflict
        ));
        assert!(matches!(
            cls(ERR_ITEM_NOT_FOUND, None),
            RpcError::ItemNotFound
        ));
        assert!(matches!(cls(ERR_VAULT_EXISTS, None), RpcError::VaultExists));
        // M2.9 值披露：authz.denied → 专用变体（CLI 拒绝文案路由用）
        assert!(matches!(
            cls(lk_core::ipc::ERR_AUTHZ_DENIED, None),
            RpcError::AuthzDenied
        ));
        assert!(matches!(
            cls(ERR_WEAK_PASSWORD, None),
            RpcError::WeakPassword
        ));
        assert!(matches!(
            cls(ERR_SYNC_NOT_CONFIGURED, None),
            RpcError::SyncNotConfigured { .. }
        ));
        assert!(matches!(
            cls(ERR_SYNC_STORAGE, None),
            RpcError::SyncStorage { .. }
        ));
        assert!(matches!(
            cls(ERR_SYNC_ANOMALY, None),
            RpcError::SyncAnomaly { .. }
        ));
        assert!(matches!(
            cls(ERR_SYNC_CREDENTIALS, None),
            RpcError::SyncCredentials { .. }
        ));
        assert!(matches!(
            cls(crate::bridge::ERR_BRIDGE_NO_DAEMON, None),
            RpcError::BridgeNoDaemon { .. }
        ));
        assert!(matches!(
            cls(crate::bridge::ERR_BRIDGE_VERSION_INCOMPATIBLE, None),
            RpcError::BridgeVersionIncompatible { .. }
        ));
        assert!(matches!(
            cls(crate::bridge::ERR_BRIDGE_IO, None),
            RpcError::BridgeIo { .. }
        ));

        match cls(ERR_LIMIT, Some(json!({"detail": "附件 > 50MB"}))) {
            RpcError::Limit { detail } => assert_eq!(detail, "附件 > 50MB"),
            other => panic!("{other:?}"),
        }
        match cls(ERR_RATE_LIMITED, Some(json!({"retryAfterSeconds": 30}))) {
            RpcError::RateLimited {
                retry_after_seconds,
            } => assert_eq!(retry_after_seconds, 30),
            other => panic!("{other:?}"),
        }
        // retryAfterSeconds 缺失 → 0（同重构前）
        match cls(ERR_RATE_LIMITED, None) {
            RpcError::RateLimited {
                retry_after_seconds,
            } => assert_eq!(retry_after_seconds, 0),
            other => panic!("{other:?}"),
        }
        // 标准段与应用段未知码都归 Other 并保留原文（code 原值兜底保留）
        for code in [ERR_METHOD_NOT_FOUND, ERR_INVALID_PARAMS] {
            match cls(code, Some(json!({"detail": "d"}))) {
                RpcError::Other {
                    code: c,
                    message,
                    detail,
                } => {
                    assert_eq!(c, code);
                    assert_eq!(message, "m");
                    assert_eq!(detail, "d");
                }
                other => panic!("{other:?}"),
            }
        }
    }

    // ------------------------- 机器可读错误名（issue #103 契约） -------------------------

    /// 每个变体的机器可读名在 CLI 内唯一（error 名是 skill 的主匹配键）；
    /// code 只作兜底——-32014 双义正是靠 name 消歧的实证。
    #[test]
    fn machine_names_unique_with_codes() {
        let cases: Vec<(RpcError, &str, i64)> = vec![
            (RpcError::VaultInvalid, "vault.invalid", -32001),
            (RpcError::SessionInvalid, "session.invalid", -32002),
            (RpcError::AuthzDenied, "authz.denied", -32017),
            (RpcError::ItemConflict, "item.conflict", -32003),
            (RpcError::ItemNotFound, "item.not_found", -32004),
            (RpcError::Limit { detail: "d".into() }, "item.limit", -32005),
            (
                RpcError::RateLimited {
                    retry_after_seconds: 3,
                },
                "rate.limited",
                -32006,
            ),
            (RpcError::VaultExists, "vault.exists", -32007),
            (RpcError::WeakPassword, "vault.weak_password", -32013),
            (
                RpcError::SyncNotConfigured {
                    detail: String::new(),
                },
                "sync.not_configured",
                -32009,
            ),
            (
                RpcError::SyncStorage {
                    detail: "5xx".into(),
                },
                "sync.storage",
                -32010,
            ),
            (
                RpcError::SyncAnomaly { detail: "x".into() },
                "sync.data_anomaly",
                -32011,
            ),
            (
                RpcError::SyncCredentials { detail: "x".into() },
                "sync.credentials",
                -32012,
            ),
            (RpcError::ChannelForbidden, "channel.forbidden", -32014),
            (
                RpcError::BridgeNoDaemon {
                    detail: String::new(),
                },
                "bridge.no_daemon",
                -32014,
            ),
            (
                RpcError::BridgeVersionIncompatible {
                    detail: String::new(),
                },
                "bridge.version_incompatible",
                -32015,
            ),
            (
                RpcError::BridgeIo {
                    detail: "io".into(),
                },
                "bridge.io",
                -32016,
            ),
            // CLI 本地失败（无服务端错误码）→ code 0
            (
                RpcError::Transport {
                    message: "无法连接守护进程".into(),
                },
                "transport",
                0,
            ),
            (
                RpcError::BadResponse {
                    message: "空响应".into(),
                },
                "bad_response",
                0,
            ),
        ];
        let mut names: Vec<&str> = cases.iter().map(|(_, n, _)| *n).collect();
        names.sort_unstable();
        let dupes = names.windows(2).filter(|w| w[0] == w[1]).count();
        assert_eq!(dupes, 0, "机器可读名必须 CLI 内唯一");
        for (err, name, code) in cases {
            assert_eq!(err.machine(), (name, code), "{err:?}");
        }
    }

    /// -32014 双义消歧（issue #103）：同一数字码按错误来源分型——daemon
    /// 错误帧 message=channel.forbidden（socket 提交 approval.result 被拒），
    /// bridge 错误帧 message=bridge.no_daemon（中继找不到守护实例）。
    #[test]
    fn code_32014_disambiguates_by_message() {
        let daemon = RpcError::classify(-32014, "channel.forbidden".into(), None);
        assert!(matches!(daemon, RpcError::ChannelForbidden));
        assert_eq!(daemon.machine(), ("channel.forbidden", -32014));

        let bridge = RpcError::classify(-32014, "bridge.no_daemon".into(), None);
        assert!(matches!(bridge, RpcError::BridgeNoDaemon { .. }));
        assert_eq!(bridge.machine(), ("bridge.no_daemon", -32014));
    }

    /// 未知服务端码（标准段/应用段）→ error 名归 other，code 保留原始数字
    /// （code 只作兜底键，不能丢）。
    #[test]
    fn unknown_codes_map_to_other_with_raw_code() {
        use lk_core::ipc::{ERR_INVALID_PARAMS, ERR_METHOD_NOT_FOUND};
        for code in [ERR_METHOD_NOT_FOUND, ERR_INVALID_PARAMS, -32099] {
            let e = RpcError::classify(code, "whatever".into(), None);
            assert_eq!(e.machine(), ("other", code));
        }
    }

    /// transport 失败变体原样穿透 client 各方法（不吞不改）。
    #[test]
    fn transport_error_propagates_untouched() {
        let mut c = RpcClient::new(|_, _| -> Result<Value, RpcError> {
            Err(RpcError::Transport {
                message: "无法连接守护进程：boom".into(),
            })
        });
        assert!(matches!(
            c.vault_lock(),
            Err(RpcError::Transport { ref message }) if message == "无法连接守护进程：boom"
        ));
        assert!(matches!(
            c.item_delete("x"),
            Err(RpcError::Transport { .. })
        ));
    }

    /// 业务 error 帧经 client 方法透出为对应变体（fake 直接走 classify）。
    #[test]
    fn business_error_surfaces_through_method() {
        let rec = Recorder::default();
        let mut c = err_client(&rec, -32002, "session.invalid", None);
        assert!(matches!(c.vault_lock(), Err(RpcError::SessionInvalid)));
        let rec = Recorder::default();
        let mut c = err_client(&rec, -32003, "item.conflict", None);
        assert!(matches!(c.item_get("x"), Err(RpcError::ItemConflict)));
    }

    // ------------------------- 响应行解析 -------------------------

    /// parse_response_line：result 帧 / error 帧 / 非法帧 / 空 result+error。
    #[test]
    fn parse_response_line_variants() {
        use lk_core::ipc::{RpcResponse, ERR_SESSION_INVALID};
        let line = serde_json::to_string(&RpcResponse::ok(json!(1), json!({"ok": true}))).unwrap();
        assert_eq!(parse_response_line(&line).unwrap(), json!({"ok": true}));

        let line = serde_json::to_string(&RpcResponse::err(
            json!(1),
            ERR_SESSION_INVALID,
            "session.invalid",
            None,
        ))
        .unwrap();
        assert!(matches!(
            parse_response_line(&line),
            Err(RpcError::SessionInvalid)
        ));

        // 非法帧 → ERR_PARSE 兜底 → Other{message:"响应解析失败"}（同重构前文案）
        match parse_response_line("not-json") {
            Err(RpcError::Other { message, .. }) => {
                assert_eq!(message, "响应解析失败");
            }
            other => panic!("{other:?}"),
        }

        // result 与 error 双缺 → 空响应
        let blank = serde_json::to_string(&RpcResponse {
            jsonrpc: "2.0".into(),
            id: json!(1),
            result: None,
            error: None,
        })
        .unwrap();
        assert!(matches!(
            parse_response_line(&blank),
            Err(RpcError::BadResponse { ref message }) if message == "空响应"
        ));
    }
}
