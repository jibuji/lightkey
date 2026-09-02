//! 本地 IPC 协议（规格：`docs/ipc.md`）。
//!
//! - 协议：**JSON-RPC 2.0**（`jsonrpc`/`method`/`params`/`id`/`result`/`error`），
//!   serde 序列化；版本前缀方法名（`vault.unlock`、`item.get`…）。
//! - 方法表见模块内常量；M1 已实现 `sync.trigger` / `sync.poll`；M2 已实现
//!   `authz.evaluate` / `approval.result` / `rule.add|list|remove` 与
//!   `subscribe`（通知订阅，决策 #3 A）。
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
/// 主密码不满足最小长度（`vault.init`/`vault.recover` 设置新主密码时）。
pub const ERR_WEAK_PASSWORD: i64 = -32013;
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
/// 审批回传等信任敏感方法仅限桌面内嵌直调（#72/#78：审批通道信任绑定，
/// authorization-gate.md §6 / 补充拍板 #16；socket 连接一律拒绝）。
pub const ERR_CHANNEL_FORBIDDEN: i64 = -32014;
pub const MSG_CHANNEL_FORBIDDEN: &str = "channel.forbidden";
/// 值披露裁决拒绝（M2.9 值披露，value-disclosure.md §5.4）：读/导出未命中
/// 规则且未批准/超时/无 UI/启动者未知——统一不区分原因，防探测。
/// （spec 原定 -32015，但 -32014~-32016 已被 lk-cli bridge 错误码占用
/// （ERR_BRIDGE_*，M2.75），撞码会使 bridge.version_incompatible 被误分类；
/// 取顺次空闲码 -32017，语义不变。）
pub const ERR_AUTHZ_DENIED: i64 = -32017;
pub const MSG_AUTHZ_DENIED: &str = "authz.denied";

pub const MSG_VAULT_INVALID: &str = "vault.invalid";
pub const MSG_SESSION_INVALID: &str = "session.invalid";
pub const MSG_ITEM_CONFLICT: &str = "item.conflict";
pub const MSG_ITEM_NOT_FOUND: &str = "item.not_found";
pub const MSG_LIMIT: &str = "item.limit";
pub const MSG_RATE_LIMITED: &str = "rate.limited";
pub const MSG_VAULT_EXISTS: &str = "vault.exists";
pub const MSG_WEAK_PASSWORD: &str = "vault.weak_password";
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
// M1：同步（M1 已实现）
pub const M_SYNC_TRIGGER: &str = "sync.trigger";
pub const M_SYNC_POLL: &str = "sync.poll";
// M2：授权门 + 规则 + 审批回传 + 通知订阅（决策 #6：`rule.add/list/remove`；
// 顶层阻塞判定 `authz.evaluate`；审批回传 `approval.result`——`approval.request`
// 已移除，其语义并入 `ApprovalChannel::open` trait）
pub const M_AUTHZ_EVALUATE: &str = "authz.evaluate";
pub const M_APPROVAL_RESULT: &str = "approval.result";
pub const M_RULE_ADD: &str = "rule.add";
pub const M_RULE_LIST: &str = "rule.list";
pub const M_RULE_REMOVE: &str = "rule.remove";
/// 通知订阅（决策 #3 A）：客户端连接后发 `subscribe`，连接转入流模式，
/// 守护进程主动写 JSON-RPC notification 帧（无 `id`，一行一帧）。
pub const M_SUBSCRIBE: &str = "subscribe";

// ---------------------------------------------------------------------------
// 通知名 / 通道（协议面 Rust 权威源；TS 镜像 = frontend/src/ipc/protocol.ts，
// 双向对齐由 frontend/src/__tests__/protocolContract.test.ts 钉死）
// ---------------------------------------------------------------------------

/// 通知帧方法名（JSON-RPC notification，无 `id`，决策 #3 A）。bus.rs
/// [`crate::bus::VaultEvent::name`] 引用本组常量——通知名只在协议模块
/// 定义一次，notifier 与 TS 侧不再手写字面量。
pub const NOTIFY_ITEM_CHANGED: &str = "item.changed";
pub const NOTIFY_SESSION_UNLOCKED: &str = "session.unlocked";
pub const NOTIFY_SESSION_LOCKED: &str = "session.locked";
pub const NOTIFY_AUTHZ_REQUEST: &str = "authz.request";

/// 审计通道值（请求 `channel` 参数；规则/值披露方法按来源标注）。
pub const CHANNEL_CLI: &str = "cli";
pub const CHANNEL_WSL_BRIDGE: &str = "wsl-bridge";
pub const CHANNEL_DESKTOP: &str = "desktop";

/// 携带 `channel` 参数的方法（授权门 + 规则 + 值披露裁决）。CLI / 桥 /
/// 桌面三侧据此覆写来源标注（main.rs bridge 覆写、client.rs 钉 "cli"、
/// tauriAdapter 钉 "desktop" 共享本清单，见 frontend/src/ipc/protocol.ts）。
pub const CHANNEL_BEARING_METHODS: &[&str] = &[
    M_AUTHZ_EVALUATE,
    M_RULE_ADD,
    M_RULE_LIST,
    M_RULE_REMOVE,
    M_ITEM_GET,
    M_ITEM_EXPORT,
];

// ---------------------------------------------------------------------------
// 各方法参数/结果类型（最小字段）
// ---------------------------------------------------------------------------

/// `vault.status` 结果：解锁态、库是否已初始化、版本、同步水位。
/// `initialized=false` = 首次启动（前端据此进入初始化向导，M2.5）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResult {
    pub unlocked: bool,
    /// 库是否已初始化（`vault.json` 存在）；无库 = 首启 → 初始化向导。
    pub initialized: bool,
    pub version: String,
    /// 同步水位（M1 起有值；M0 恒为 null）。
    pub sync_watermark: Option<String>,
    /// 审计锚点状态（issue #75）：锚点可用且链未被截断 = true。降级到
    /// 侧写 / 锚点缺失 / 检测到截断 = false。桌面 UI 可据此给用户警告。
    /// 可选字段（旧守护进程/协议兼容；缺省 = 未知，前端按 undefined 处理）。
    #[serde(default)]
    pub audit_anchor_ok: bool,
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
///
/// M2.9 值披露：请求/响应形状不变；`channel` 为**可选审计来源标注**
/// （spec §8——`wsl-bridge` 客户端标注优先，缺省按对端来源，与
/// `rule.*` 同口径），不参与裁决。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemGetParams {
    pub id: Uuid,
    /// 审计来源标注（`cli` | `desktop` | `wsl-bridge`；缺省按对端来源）。
    #[serde(default)]
    pub channel: Option<String>,
}

/// `item.delete` 参数（软删除 → 墓碑）。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemDeleteParams {
    pub id: Uuid,
}

/// `item.export` 参数（file 类型整包下载，M0 单机；分块协议 M1）。
/// `channel` 语义同 [`ItemGetParams::channel`]（spec §8）。
#[derive(Debug, Clone, Deserialize)]
pub struct ItemExportParams {
    pub id: Uuid,
    /// 审计来源标注（`cli` | `desktop` | `wsl-bridge`；缺省按对端来源）。
    #[serde(default)]
    pub channel: Option<String>,
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

/// `audit.verify` 结果：成功验证的事件数（含轮换链语义）+ 锚点交叉核对结果。
/// `truncated` 为 true 时表示链比可信锚点短（或锚点缺失）——截断检测，调用方
/// 应报错并退出非零（issue #75）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditVerifyResult {
    pub verified: usize,
    /// 锚点是否建立且与链一致（true）。降级侧写仍可 true（有锚点但不是平台）。
    pub anchor_ok: bool,
    /// 锚点当前是否降级到侧写文件（平台 keychain 不可用）。
    pub anchor_degraded: bool,
    /// 检测到截断 / 锚点缺失（调用方须报「truncation detected」）。
    pub truncated: bool,
    /// 校验时链的事件总数。
    pub chain_ordinal: usize,
    /// 锚点记录的 ordinal（无锚点 = null）。
    pub anchor_ordinal: Option<u64>,
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

// ---------------------------------------------------------------------------
// M2：授权门 / 规则 / 审批回传 / 通知订阅
// ---------------------------------------------------------------------------

/// `authz.evaluate` 参数。
///
/// **守护进程侧派生，不信任客户端**（authorization-gate.md §3）：`starter`/
/// `cwd` 字段即使携带也一律忽略——启动者与工作目录以 IPC 对端 PID 回溯
/// 结果为准（伪造 cwd 绕过必须失败）。`channel` 仅作审计来源标注。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthzEvaluateParams {
    /// 具名命令（如 `npm publish`；匹配规则 command glob）。
    pub command: String,
    /// 请求注入的 key 名（值不可见、名可指名，决策 #1）。
    pub keys: Vec<String>,
    /// 审计来源标注（`cli` | `desktop` | `wsl-bridge`；缺省 = cli；
    /// `wsl-bridge` = WSL 内客户端经 interop 桥，cross-subsystem.md §7.5）。
    #[serde(default)]
    pub channel: Option<String>,
    /// 客户端自报 cwd（**仅供提示，判定一律以对端真实 cwd 为准**）。
    #[serde(default)]
    pub cwd: Option<String>,
}

/// `authz.evaluate` 结果（最小字段：只含被批准命令的 env 变量，ipc.md §4）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthzEvaluateResult {
    pub allowed: bool,
    /// `allowed=false` 时的拒绝原因（`denied` | `timeout` | 细分 reason）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `allowed=true` 时被批准注入的 env（key 名 → 值；只含被授权 key）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<std::collections::BTreeMap<String, String>>,
}

/// `approval.result` 参数（审批回传；决策权始终在 Rust 侧，§5.3）。
///
/// #72/#78：本方法仅接受**桌面内嵌直调**（socket 连接 →
/// `channel.forbidden`）；`challenge` 为 `authz.request` 广播帧携带的
/// 一次性应答值，必须原样回带（错值 → `accepted=false`，条目保留）。
///
/// 锁定态一体化审批（#67）：`needs_unlock` 的待审条目要求允许决策时携带
/// `masterPassword`——守护进程以之做**临时解锁**（仅本次注入可用，不签发
/// 会话令牌）。错误主密码计 AuthGuard 失败（防暴破），并以错误响应退回
/// 弹窗（条目保留，倒计时内可重试）；解锁成功才 `resolve`。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResultParams {
    pub request_id: Uuid,
    /// `allowed` | `denied`（timeout 由守护进程侧超时产生，客户端不可发）。
    pub decision: String,
    /// 一次性审批挑战（#78 方案 B）。
    pub challenge: String,
    /// 锁定态一体化的主密码（可选：仅 `needs_unlock` 待审且 decision=
    /// `allowed` 时使用并校验；其余情况忽略）。决不在审计/日志中出现。
    #[serde(default)]
    pub master_password: Option<String>,
}

/// `approval.result` 结果：是否被守护进程接受（伪造/已超时的 requestId
/// 被忽略 → `accepted=false`）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalResultOutcome {
    pub accepted: bool,
}

/// `rule.add` 参数（决策 #6：规则含 `name`；写入唯一合法路径之一）。
///
/// M2.9 值披露（value-disclosure.md §4）：`capability` 选规则能力类型——
/// `inject`（注入，默认）或 `read`（读值；`command` 必须为空串）。
/// M2.97 写门（write-gate.md §7）：`capability=write` + `actions` 写动作
/// 子集（缺省 create+update；**delete 不是合法动作**——恒弹窗由协议保证）；
/// capability != write 时忽略。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleAddParams {
    /// 规范化绝对路径（守护进程侧 canonicalize 校验）；跨命名空间场景为
    /// `wsl://<distro>/<rest>` 规范形（守护进程侧经 [`crate::path_ns`] 归一化）。
    pub project_dir: String,
    pub name: String,
    /// 具名命令（可 glob）；capability=read/write 时空串。
    pub command: String,
    pub keys: Vec<String>,
    /// 规则能力类型（`inject` | `read` | `write`；缺省 inject）。
    #[serde(default)]
    pub capability: Option<String>,
    /// write 能力下的写动作子集（缺省 create+update；capability != write
    /// 时忽略）。加性字段，协议零新增（write-gate.md §7）。
    #[serde(default)]
    pub actions: Option<Vec<String>>,
    /// 程序指纹绑定请求（M2.98，identity-binding.md §4/§5.3）：`Some` 时
    /// 规则**绑定**该可执行文件。`exe_path` 为要绑定的 canonical 绝对路径；
    /// **daemon 不信任客户端上报的 size/sha256**——审批 finalize 侧重算
    /// （identity-binding.md §5.3），此处仅声明「绑哪个可执行文件」。
    /// serde(default)=None → 既有 rule.add（未绑定）零迁移。
    #[serde(default)]
    pub fingerprint: Option<crate::model::ProgramFingerprint>,
    /// 审计来源标注（`cli` | `desktop` | `wsl-bridge`；缺省 = cli）。
    #[serde(default)]
    pub channel: Option<String>,
}

/// `rule.add` 结果：完整规则。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleAddResult {
    pub rule: crate::model::Rule,
}

/// `rule.list` 结果（最小字段：规则全字段，无密钥值）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleListResult {
    pub rules: Vec<crate::model::Rule>,
}

/// `rule.remove` 参数。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleRemoveParams {
    pub id: Uuid,
    /// 审计来源标注（`cli` | `desktop` | `wsl-bridge`；缺省 = cli）。
    #[serde(default)]
    pub channel: Option<String>,
}

/// 规则字段校验（超长/非法 → `Err`，不入库；testing.md 第三层 #19）。
///
/// - `capability`：`inject` | `read` | `write`（值披露裁决 value-disclosure.md
///   §4 + 写门 write-gate.md §4；能力不互授——校验层面即强制 inject 规则带
///   命令、read/write 规则不带命令）；
/// - `projectDir`：绝对路径且可 canonicalize（存在）；**合法**的
///   `wsl://<distro>[/<rest>]` 跨命名空间规范形（[`crate::path_ns`]，守护进程
///   侧已归一化）例外——非本机文件系统路径，无法 canonicalize，仅接受该形态
///   本身（缺 distro 段等畸形形态一律拒绝）；
/// - `command`：inject 时非空、≤ 1024、无控制字符；read/write 时必须为空串；
/// - `name`：非空、≤ 256、无控制字符；
/// - `keys`：1..=32 个，均为合法环境变量名（`[A-Za-z_][A-Za-z0-9_]*`；
///   read/write 规则语义为条目名，同一约束）；
/// - `actions`：仅 capability=write 时校验——非空且为 create/update 子集，
///   **含 `delete` 拒绝**（删除恒弹窗由协议保证，规则写不进去）；
///   capability != write 时忽略（调用方按 serde 缺省落库）。
pub fn validate_rule_fields(
    capability: &str,
    project_dir: &str,
    name: &str,
    command: &str,
    keys: &[String],
    actions: &[String],
) -> std::result::Result<(), String> {
    if capability != crate::model::RULE_CAPABILITY_INJECT
        && capability != crate::model::RULE_CAPABILITY_READ
        && capability != crate::model::RULE_CAPABILITY_WRITE
    {
        return Err("capability 必须是 inject、read 或 write".into());
    }
    if !crate::path_ns::is_valid_wsl_canonical(project_dir) {
        if project_dir.is_empty() || !std::path::Path::new(project_dir).is_absolute() {
            return Err("projectDir 必须是绝对路径".into());
        }
        if std::fs::canonicalize(project_dir).is_err() {
            return Err(format!("projectDir 无法解析：{project_dir}"));
        }
    }
    if name.is_empty() || name.len() > 256 || has_control_chars(name) {
        return Err("name 必须是非空、≤256 字符且无控制字符的规则名".into());
    }
    match capability {
        crate::model::RULE_CAPABILITY_READ | crate::model::RULE_CAPABILITY_WRITE => {
            if !command.is_empty() {
                return Err("read/write 规则不绑定命令（command 必须为空）".into());
            }
        }
        _ => {
            if command.is_empty() || command.len() > 1024 || has_control_chars(command) {
                return Err("command 必须是非空、≤1024 字符且无控制字符的命令".into());
            }
        }
    }
    if capability == crate::model::RULE_CAPABILITY_WRITE {
        if actions.is_empty() {
            return Err("actions 不能为空（写规则至少一个动作：create、update）".into());
        }
        if let Some(bad) = actions.iter().find(|a| {
            a.as_str() != crate::model::RULE_ACTION_CREATE
                && a.as_str() != crate::model::RULE_ACTION_UPDATE
        }) {
            if bad == "delete" {
                // 恒弹窗由协议保证（write-gate.md §3/§4）：任何规则不豁免
                // delete，规则也不该写得进去——尽早拒绝并点破语义。
                return Err(
                    "actions 不接受 delete（删除恒弹窗，任何规则不豁免；actions 只允许 create、update）".into(),
                );
            }
            return Err(format!(
                "非法写动作：{bad}（actions 只允许 create、update）"
            ));
        }
    }
    if keys.is_empty() || keys.len() > 32 {
        return Err("keys 必须是 1~32 个 key 名".into());
    }
    let valid_name = |k: &str| {
        let mut chars = k.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(bad) = keys.iter().find(|k| !valid_name(k)) {
        return Err(format!(
            "非法 key 名：{bad}（须为环境变量名 [A-Za-z_][A-Za-z0-9_]*）"
        ));
    }
    Ok(())
}

/// `authz.evaluate` 的 keys/command 参数校验（同规则字段规则）。
pub fn validate_evaluate_fields(command: &str, keys: &[String]) -> std::result::Result<(), String> {
    if command.is_empty() || command.len() > 4096 || has_control_chars(command) {
        return Err("command 必须是非空、≤4096 字符且无控制字符的命令".into());
    }
    if keys.is_empty() || keys.len() > 32 {
        return Err("keys 必须是 1~32 个 key 名".into());
    }
    let valid_name = |k: &str| {
        let mut chars = k.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return false,
        }
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    };
    if let Some(bad) = keys.iter().find(|k| !valid_name(k)) {
        return Err(format!(
            "非法 key 名：{bad}（须为环境变量名 [A-Za-z_][A-Za-z0-9_]*）"
        ));
    }
    Ok(())
}

fn has_control_chars(s: &str) -> bool {
    s.chars().any(|c| c.is_control())
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

    /// 规则字段校验（M2.97 写门，write-gate.md §4/§7）：capability=write
    /// 放行；actions 只接受 create/update 非空子集，delete 恒弹窗写不进去；
    /// capability != write 时 actions 忽略。
    #[test]
    fn validate_rule_fields_write_capability_and_actions() {
        let proj = std::env::temp_dir().to_string_lossy().to_string();
        let ok = |capability: &str, command: &str, actions: &[&str]| {
            let actions: Vec<String> = actions.iter().map(|s| s.to_string()).collect();
            let keys = ["K".to_string()];
            validate_rule_fields(capability, &proj, "w", command, &keys, &actions)
        };
        // write + actions 非空 create/update 子集 + 无命令绑定 → 放行
        for actions in [
            vec!["create", "update"], // 缺省集（调用方展开 serde 缺省后传入）
            vec!["create"],
            vec!["update"],
        ] {
            assert!(ok("write", "", &actions).is_ok(), "应放行：{actions:?}");
        }
        // delete 拒绝且文案点破恒弹窗（协议保证，规则不该也写不进去）
        let e = ok("write", "", &["delete"]).unwrap_err();
        assert!(
            e.contains("delete") && e.contains("弹窗"),
            "文案不清晰：{e}"
        );
        // 子集混入 delete 同样拒绝
        assert!(ok("write", "", &["create", "delete"]).is_err());
        // 空 actions / 非法动作名拒绝
        assert!(ok("write", "", &[]).is_err());
        let e = ok("write", "", &["bogus"]).unwrap_err();
        assert!(e.contains("bogus"), "文案应指出非法动作：{e}");
        // write 规则不绑定命令（与 read 同款）
        assert!(ok("write", "npm *", &["create"]).is_err());
        // capability != write：actions 忽略（不校验、不拒）
        assert!(ok("inject", "npm *", &["bogus"]).is_ok());
        assert!(ok("read", "", &["create"]).is_ok());
        // 未知 capability 仍拒绝，文案覆盖三能力
        let e = ok("admin", "", &[]).unwrap_err();
        assert!(e.contains("inject") && e.contains("read") && e.contains("write"));
    }
}
