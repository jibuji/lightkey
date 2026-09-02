//! Agent 授权门（规格：`docs/authorization-gate.md`；M2 落地）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - 三层模型作为**硬编码确定性流程**（`waterfall` 语义，命中即短路，
//!   不数据化，plugin-architecture.md §5.4）：① 默认拒绝 → ② 规则白名单
//!   （vault 内加密、按项目目录绑定）→ ③ 弹窗审批（30s 超时默认拒绝）。
//! - 启动者判定（[`crate::starter`]）由**守护进程**从 IPC 对端 PID 回溯，
//!   客户端自报 `starter/cwd` 一律视为不可信输入。
//! - 规则匹配：`projectDir` 祖先匹配（canonical 形态）+ `command` glob
//!   （`*`/`?`，大小写敏感）；多规则命中取 **keys 并集**；注入集合 =
//!   规则 keys ∩ 请求 keys（agent 只能看到被授权的 key 名）。
//! - 审批通道抽象成接口（[`ApprovalChannel`]）：本地实现
//!   （[`LocalApprovalChannel`]，桌面弹窗 + 30s 超时）；远程留接口不实现
//!   （P1 不做）。
//! - 授权门三层是 Rust 内部确定性流程；`authz.request`（[`bus::VaultEvent`]）
//!   只是「需要用户决策」的通知，决策权始终在 Rust 侧（§5.3）。
//! - **G1 并发约束**：第 3 层的 30s 等待不得持有守护进程命令锁——实现为
//!   三阶段（[`AuthzGate::begin`] 命令锁内 → [`AuthzGate::await_decision`]
//!   锁外等待 → 守护进程重取锁收尾），见 `lk-daemon` 装配。
//! - fail-closed：启动者未知 / 规则库损坏（解密失败）/ 无审批界面 /
//!   请求 key 无法解析 → 一律拒绝，不弹窗、不留内容，仅审计拒绝事件。

use std::collections::HashSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::bus::{EventBus, VaultEvent};
use crate::model::Rule;
use crate::Result;

/// 审批超时默认值（第 3 层弹窗 30s 超时默认拒绝；守护进程配置可调，默认 30）。
pub const APPROVAL_TIMEOUT_DEFAULT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// 请求 / 决策类型
// ---------------------------------------------------------------------------

/// 授权判定请求（**全部由守护进程侧派生/核对**，不信任客户端自报字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthzRequest {
    /// 启动者（进程链回溯结果；`unknown` = fail-closed 拒绝）。
    pub starter: String,
    /// 对端进程真实 cwd（canonical 形态）。
    pub cwd: String,
    /// 具名命令（如 `npm publish`；匹配规则 command glob）。
    pub command: String,
    /// 请求注入的 key 名集合（值不可见、名可指名，决策 #1）。
    pub keys: Vec<String>,
}

/// 三层判定的中间/最终结果（`evaluate_layers` 为非阻塞的第 1/2 层短路）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayerResult {
    /// 第 2 层规则命中：注入 `keys`（规则 keys ∩ 请求 keys）。
    Allowed { keys: Vec<String> },
    /// 第 1 层拒绝（fail-closed；不弹窗、不留内容）。
    Denied { reason: DenyReason },
    /// 未命中规则 → 进入第 3 层弹窗审批。
    NeedsApproval,
}

/// 拒绝原因（审计与 CLI 文案映射用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// 启动者未知（进程链回溯失败/跨会话）→ fail-closed。
    UnknownStarter,
    /// 对端 cwd 不可得（回溯失败）→ fail-closed（规则按项目目录绑定）。
    NoCwd,
    /// 请求的 key 无法在库中解析（不存在/非 secret 类型）→ 无法满足请求。
    MissingKeys,
    /// 规则库损坏（解密失败）→ fail-closed。
    RuleCorrupt,
    /// 无审批界面（无推送订阅连接）→ 第 3 层立即拒绝，不阻塞。
    NoUi,
    /// 用户拒绝。
    Rejected,
    /// 审批超时（默认拒绝）。
    Timeout,
}

impl DenyReason {
    /// 协议面字符串（`authz.evaluate` 响应的 `reason` 字段）。
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::UnknownStarter => "unknown_starter",
            DenyReason::NoCwd => "no_cwd",
            DenyReason::MissingKeys => "missing_keys",
            DenyReason::RuleCorrupt => "rule_corrupt",
            DenyReason::NoUi => "no_ui",
            DenyReason::Rejected => "rejected",
            DenyReason::Timeout => "timeout",
        }
    }
}

/// 审批通道决策（第 3 层结果三态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Allowed,
    Denied,
    Timeout,
}

/// 审批请求类型（M2.9 值披露；弹窗按 kind 选形态，value-disclosure.md §6；
/// 补充拍板 #22 增 `Rule`，#24 增 `Write`）。加性变更，不升协议版本。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalKind {
    /// 命令注入（既有 inject 语义）。
    Inject,
    /// 读条目值（`item.get`；读规则命中则不产生审批）。
    Read,
    /// 导出条目数据包（`item.export`；恒弹窗，规则不豁免）。
    Export,
    /// 规则管理（`rule.add` / `rule.remove`；补充拍板 #22）。单一 kind +
    /// `command` 字段承载操作（`rule.add <name>` / `rule.remove <name>`），
    /// 不拆两个 kind——remove 由 daemon 解析 id→规则补全 name/keys/projectDir
    /// 供弹窗展示。
    Rule,
    /// 条目写入（`item.put` / `item.delete`；M2.97 写入门，补充拍板 #24，
    /// write-gate.md §6）。单一 kind + `command` 字段承载动作
    /// （`item.put <name>` / `item.delete <name>`）；keys = 单元素
    /// [目标条目名]；export_meta 恒 None。
    Write,
}

/// export 审批的数据包元信息（弹窗展示规模用；不含数据本身）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportMeta {
    pub name: String,
    pub mime: String,
    pub size: u64,
}

/// 审批请求负载（`authz.request` 事件与弹窗展示用；keys 仅 key 名）。
///
/// `challenge` 为**一次性应答值**（#78 方案 B）：随 `open` 登记 + 仅经
/// 事件总线广播给桌面订阅者（不出现在任何 RPC 响应里），`approval.result`
/// 必须原样回带才被接受——纵使未来出现可伪造连接标签的进程内组件，无
/// 挑战值仍无法自我批准。
///
/// M2.9 值披露（value-disclosure.md §5.2/§6）：`kind` 区分注入/读/导出
/// 审批形态；`command` 字段填 `"item.get"` / `"item.export"`（展示用），
/// `keys` 为单元素 [条目名]；`export_meta` 仅 export 审批有值。
///
/// M2.98 程序指纹失配（identity-binding.md §7）：`fingerprint_mismatch` 携带
/// 「绑定注入规则命中命令形态但指纹不符」的展示信息——弹窗据「指纹不符」主题
/// 展示当前解析路径、8 位哈希摘要并给「以新指纹重新授权」入口；未失配为
/// `None`（常规审批）。**不含完整哈希、任何值或错误码差异化**（失配视同
/// 未命中，headless 统一 `authz.denied`，防探测）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintMismatch {
    /// 当前解析到的 canonical 绝对路径（daemon 侧重算；展示用，非安全依据）。
    pub resolved_exe_path: String,
    /// 8 位 SHA-256 前缀摘要（hex 小写；不展示完整值）。
    pub sha256_short: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub starter: String,
    pub project_dir: String,
    pub command: String,
    pub keys: Vec<String>,
    /// 一次性审批挑战（见结构体文档；守护进程侧生成的高熵随机值 hex）。
    pub challenge: String,
    /// 锁定态一体化（#67）：弹窗须同时收集主密码（临时解锁 + 本次授权
    /// 一次交互）；守护进程拿到 `approval.result` 的 `masterPassword` 后
    /// 先临时解锁再跑授权门，且不签发会话令牌。false = 常规解锁态审批。
    pub needs_unlock: bool,
    /// 审批类型（值披露读/导出弹窗按 kind 渲染；读/导出不带解锁一体化）。
    pub kind: ApprovalKind,
    /// export 审批的数据包规模元信息（kind=Export 时有值；读/注入为 None）。
    pub export_meta: Option<ExportMeta>,
    /// 程序指纹失配信息（M2.98，identity-binding.md §7）：绑定注入规则命中
    /// 命令形态但指纹不符时携带（弹窗据此显示「指纹不符」主题 + 当前路径 +
    /// 8 位哈希摘要 + 「以新指纹重新授权」）；未失配为 `None`。
    pub fingerprint_mismatch: Option<FingerprintMismatch>,
}

// ---------------------------------------------------------------------------
// 规则库视图（授权门对 vault 的最小读取面；测试注入假实现）
// ---------------------------------------------------------------------------

/// 授权门需要的 vault 视图：解密态规则 + 按名解析 secret 值。
pub trait RuleVault: Send + Sync {
    /// 全部解密态规则（含已删除的？——**不含**：删除规则不参与匹配）。
    /// 解密失败 → `Err`（规则库损坏 → fail-closed）。
    fn rules(&self) -> Result<Vec<Rule>>;
    /// 按 key 名解析 secret 条目值（不存在/非 secret/已删除 → `Ok(None)`）。
    fn secret_value(&self, key_name: &str) -> Result<Option<String>>;
}

// ---------------------------------------------------------------------------
// 审批通道（trait + 本地实现 + 待审批注册表）
// ---------------------------------------------------------------------------

/// 审批通道抽象（`docs/authorization-gate.md` §6；本地/远程可切换）。
///
/// 两阶段接口对应守护进程的 G1 三阶段编排（见模块文档）：
/// [`ApprovalChannel::open`]（登记 + 广播，命令锁内、非阻塞）→
/// [`ApprovalChannel::await_decision`]（命令锁外等待，超时默认拒绝）。
pub trait ApprovalChannel: Send + Sync {
    /// 是否有界面可能响应审批（桌面壳的进程内推送订阅；#72/#78 起 daemon
    /// 装配只数**桌面来源**订阅者——socket 订阅不计，见 lk-daemon 装配）。
    /// `false` → fail-closed 立即拒绝，不登记、不阻塞（authorization-gate.md §7）。
    fn available(&self) -> bool;
    /// 该通道是否会**立即自动裁决**给定类型的审批（E2E 门控，补充拍板 #22；
    /// 默认 false = 无自动路径）。仅 [`AutoApproveChannel`] 在 env 门开启时
    /// 对 [`ApprovalKind::Rule`] 返回 true；调用方据此跳过 `available()` 的
    /// UI 在场判定（inject/披露审批不受影响，照旧要求 UI）。
    fn auto_approves(&self, kind: ApprovalKind) -> bool {
        let _ = kind;
        false
    }
    /// 登记待审批 + 广播 `authz.request`（非阻塞；守护进程命令锁内调用）。
    fn open(&self, req: &ApprovalRequest, expires_at: Instant);
    /// 等待决策（守护进程命令锁外调用；最多等到 `expires_at`，超时默认拒绝）。
    fn await_decision(&self, request_id: Uuid, expires_at: Instant) -> ApprovalDecision;
}

/// 待审批条目（`expires_at` 到期即清理；决策槽供 `approval.result` 写入）。
///
/// #78 方案 A+B：`challenge` 仅随事件总线广播（桌面订阅者可见），回传时
/// 必须逐一比对——连接标签之外的纵深防御。
#[derive(Debug, Clone)]
struct PendingApproval {
    decision: Option<ApprovalDecision>,
    expires_at: Instant,
    challenge: String,
}

/// 待审批注册表（守护进程跨线程共享：命令线程登记/等待，审批回传线程写入）。
#[derive(Default)]
pub struct PendingApprovals {
    inner: Mutex<std::collections::HashMap<Uuid, PendingApproval>>,
    condvar: Condvar,
}

impl PendingApprovals {
    pub fn new() -> PendingApprovals {
        PendingApprovals::default()
    }

    /// 登记待审批（幂等：重复登记刷新到期时刻与决策槽/挑战值）。
    pub fn register(&self, request_id: Uuid, expires_at: Instant, challenge: String) {
        self.inner.lock().unwrap().insert(
            request_id,
            PendingApproval {
                decision: None,
                expires_at,
                challenge,
            },
        );
    }

    /// 回传决策（`approval.result`）：条目存在且未到期**且挑战值匹配** →
    /// 写入并唤醒等待者；未知/已超时/挑战不符 → 忽略并返回 false。
    ///
    /// - 伪造 requestId（未知/已超时）→ 移除已到期条目、返回 false；
    /// - 挑战不符（#78：无广播帧则拿不到 challenge）→ **不移除**条目，
    ///   防止伪回传把真用户的待审批请求打掉（拒绝 DoS），仅本次忽略；
    /// - 比较用普通等值判定：注册表跨进程共享内存，无逐字节侧信道面。
    pub fn resolve(&self, request_id: Uuid, decision: ApprovalDecision, challenge: &str) -> bool {
        let mut map = self.inner.lock().unwrap();
        let expired = map
            .get(&request_id)
            .map(|p| Instant::now() >= p.expires_at)
            .unwrap_or(true);
        if expired {
            map.remove(&request_id);
            return false;
        }
        let matches = map
            .get(&request_id)
            .map(|p| p.challenge == challenge)
            .unwrap_or(false);
        if !matches {
            return false;
        }
        if let Some(p) = map.get_mut(&request_id) {
            p.decision = Some(decision);
        }
        self.condvar.notify_all();
        true
    }

    /// 等待决策（命令锁外）：决策到达 → 消费并返回；到期 → 清理并返回
    /// [`ApprovalDecision::Timeout`]（默认拒绝）。到期时刻以登记值为准。
    pub fn await_decision(&self, request_id: Uuid) -> ApprovalDecision {
        let mut map = self.inner.lock().unwrap();
        loop {
            match map.get(&request_id) {
                Some(p) if p.decision.is_some() => {
                    let d = p.decision.unwrap();
                    map.remove(&request_id);
                    return d;
                }
                Some(p) if Instant::now() >= p.expires_at => {
                    map.remove(&request_id);
                    return ApprovalDecision::Timeout;
                }
                Some(p) => {
                    let remaining = p.expires_at.saturating_duration_since(Instant::now());
                    let (guard, timeout_result) = self
                        .condvar
                        .wait_timeout(map, remaining.max(Duration::from_millis(1)))
                        .unwrap();
                    map = guard;
                    if timeout_result.timed_out() {
                        // 重新评估（防止虚假唤醒/时间竞争）
                        continue;
                    }
                }
                None => {
                    // 条目已被消费/清理（竞态）→ 保守视为拒绝
                    return ApprovalDecision::Denied;
                }
            }
        }
    }

    /// 当前待审批数（测试断言用）。
    pub fn pending_count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// 把所有待审批条目的到期时刻提前到当前时刻并唤醒等待者（测试专用）：
    /// 需要同时断言「回传落地」与「超时拒绝」的测试（如 #67 错误主密码
    /// 保留条目后 CLI 侧超时）不再依赖真实秒级等待——到期判定、清理与
    /// 默认拒绝走既有 `await_decision` 语义，仅时钟被测试掌控。
    #[doc(hidden)]
    pub fn expire_all_for_tests(&self) {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        for p in map.values_mut() {
            p.expires_at = now;
        }
        self.condvar.notify_all();
    }
}

/// 本地审批通道：登记 → 广播 `authz.request` → 在注册表上等待
/// `approval.result` 或超时（30s 默认拒绝）。`available` = 推送连接存在
/// （桌面壳已订阅；无界面 fail-closed）。
pub struct LocalApprovalChannel {
    approvals: Arc<PendingApprovals>,
    bus: Arc<EventBus>,
    /// 推送连接存在性（守护进程装配的 PushHub；无订阅 = 无界面）。
    has_ui: Box<dyn Fn() -> bool + Send + Sync>,
}

impl LocalApprovalChannel {
    pub fn new(
        approvals: Arc<PendingApprovals>,
        bus: Arc<EventBus>,
        has_ui: Box<dyn Fn() -> bool + Send + Sync>,
    ) -> LocalApprovalChannel {
        LocalApprovalChannel {
            approvals,
            bus,
            has_ui,
        }
    }
}

impl ApprovalChannel for LocalApprovalChannel {
    fn available(&self) -> bool {
        (self.has_ui)()
    }

    fn open(&self, req: &ApprovalRequest, expires_at: Instant) {
        self.approvals
            .register(req.request_id, expires_at, req.challenge.clone());
        // 广播 `authz.request`（通知 D 层弹窗；无密钥值；challenge 仅经本
        // 事件通道下发——守护进程侧通知桥只投给桌面订阅者，#78 方案 A；
        // kind/export_meta 供弹窗按审批类型渲染，M2.9 值披露）
        self.bus.emit(&VaultEvent::AuthzRequest {
            request_id: req.request_id,
            starter: req.starter.clone(),
            project_dir: req.project_dir.clone(),
            command: req.command.clone(),
            keys: req.keys.clone(),
            challenge: req.challenge.clone(),
            needs_unlock: req.needs_unlock,
            kind: req.kind,
            export_meta: req.export_meta.clone(),
            fingerprint_mismatch: req.fingerprint_mismatch.clone(),
        });
    }

    fn await_decision(&self, request_id: Uuid, expires_at: Instant) -> ApprovalDecision {
        // 到期时刻以登记值为准（`expires_at` 参数为远程通道语义预留）
        let _ = expires_at;
        self.approvals.await_decision(request_id)
    }
}

/// E2E 自动批准通道（补充拍板 #22；装饰器，套在 [`LocalApprovalChannel`] 外）。
///
/// **env 门控**：daemon **启动时**读一次 [`AutoApproveChannel::ENV`]，值为
/// `rule` 时对 [`ApprovalKind::Rule`] 的审批**立即 Allowed**（登记后即刻
/// resolve，不广播 `authz.request`——无 UI 参与）。inject/读/导出审批一律
/// 不碰（`available()` 语义原样透传内层，headless 照旧 fail-closed 立即拒绝）。
///
/// 取舍（decisions #22，勿自行变更）：
/// - **release 二进制保留此路径是有意决策**——E2E 必须测发布物本体；
///   编译期 feature/cfg 门为被否选项（会测非发布物、削弱 E2E 价值）。
/// - 攻击面：env 仅在 daemon 启动时读取；攻击者自带该变量拉起的新 daemon
///   库是锁的，`rule.add` 仍过会话门（`session.invalid`），无权限增益。
/// - 审计独立标注：经此通道放行的规则变更在 daemon 侧落
///   `channel=auto-approve`（含 requestId 与规则内容），绝不静默。
pub struct AutoApproveChannel {
    inner: Arc<dyn ApprovalChannel>,
    approvals: Arc<PendingApprovals>,
    rule_enabled: bool,
}

impl AutoApproveChannel {
    /// env 变量名（值 `rule` = 仅规则审批自动批准）。
    pub const ENV: &'static str = "LIGHTKEY_E2E_AUTO_APPROVE";

    /// 生产构造：daemon 启动时读一次 env。
    pub fn new(
        inner: Arc<dyn ApprovalChannel>,
        approvals: Arc<PendingApprovals>,
    ) -> AutoApproveChannel {
        let rule_enabled = Self::env_rule_enabled();
        AutoApproveChannel {
            inner,
            approvals,
            rule_enabled,
        }
    }

    /// 当前 env 是否开启规则自动批准（`LIGHTKEY_E2E_AUTO_APPROVE=rule`）。
    pub fn env_rule_enabled() -> bool {
        std::env::var(Self::ENV).ok().as_deref() == Some("rule")
    }

    /// 测试/装配构造：显式给定门控状态（不读 env，避免并行测试竞争；
    /// lk-daemon 装配在 `Daemon::start` 读一次 env 后传入）。
    pub fn with_rule_enabled(
        inner: Arc<dyn ApprovalChannel>,
        approvals: Arc<PendingApprovals>,
        rule_enabled: bool,
    ) -> AutoApproveChannel {
        AutoApproveChannel {
            inner,
            approvals,
            rule_enabled,
        }
    }

    /// 门控当前状态（daemon 启动横幅用）。
    pub fn rule_enabled(&self) -> bool {
        self.rule_enabled
    }

    /// 测试专用：翻转门控（生产路径不调用）。
    #[doc(hidden)]
    pub fn set_rule_enabled_for_tests(&mut self, enabled: bool) {
        self.rule_enabled = enabled;
    }
}

impl ApprovalChannel for AutoApproveChannel {
    fn available(&self) -> bool {
        // UI 在场性不因 E2E 门改变：inject/披露审批照旧据此 fail-closed
        self.inner.available()
    }

    fn auto_approves(&self, kind: ApprovalKind) -> bool {
        self.rule_enabled && kind == ApprovalKind::Rule
    }

    fn open(&self, req: &ApprovalRequest, expires_at: Instant) {
        if self.auto_approves(req.kind) {
            // 登记 + 立即 Allowed（同一挑战值 resolve；等待者即刻拿到决策）；
            // 不广播 authz.request——自动批准无 UI 参与，弹窗不该出现
            self.approvals
                .register(req.request_id, expires_at, req.challenge.clone());
            let _ =
                self.approvals
                    .resolve(req.request_id, ApprovalDecision::Allowed, &req.challenge);
            return;
        }
        self.inner.open(req, expires_at);
    }

    fn await_decision(&self, request_id: Uuid, expires_at: Instant) -> ApprovalDecision {
        // 内外层共用同一注册表（装饰器只改 open 的规则分支）
        self.inner.await_decision(request_id, expires_at)
    }
}

// ---------------------------------------------------------------------------
// 授权门（三层模型，硬编码确定性流程）
// ---------------------------------------------------------------------------

/// B 层 **authz-gate** 插件（`docs/plugin-architecture.md` §3.2；注入
/// session + audit + vault-store + approval）。`Send + Sync`：守护进程
/// 命令线程与审批回传线程共享。
pub struct AuthzGate {
    approval: Arc<dyn ApprovalChannel>,
}

impl AuthzGate {
    /// 装配审批通道（守护进程注入 [`LocalApprovalChannel`]；远程留接口）。
    pub fn new(approval: Arc<dyn ApprovalChannel>) -> AuthzGate {
        AuthzGate { approval }
    }

    /// 审批通道引用（守护进程等待决策用）。
    pub fn approval(&self) -> &Arc<dyn ApprovalChannel> {
        &self.approval
    }

    /// 第 1/2 层（**非阻塞**；守护进程命令锁内调用）：
    ///
    /// 1. 默认拒绝：启动者未知 / cwd 不可得 / 请求 key 无法解析 /
    ///    规则库损坏 → [`LayerResult::Denied`]（fail-closed，不弹窗）；
    /// 2. 规则白名单：`(projectDir, command)` 匹配（祖先 + glob）→ 命中
    ///    取多规则 keys **并集 ∩ 请求 keys** → [`LayerResult::Allowed`]；
    /// 3. 未命中 → [`LayerResult::NeedsApproval`]（进入弹窗审批）。
    pub fn evaluate_layers(&self, req: &AuthzRequest, vault: &dyn RuleVault) -> LayerResult {
        // 第 1 层：fail-closed 检查
        if req.starter == crate::starter::UNKNOWN_STARTER {
            return LayerResult::Denied {
                reason: DenyReason::UnknownStarter,
            };
        }
        if req.cwd.is_empty() {
            return LayerResult::Denied {
                reason: DenyReason::NoCwd,
            };
        }
        // 规则库损坏（解密失败）优先于 key 解析失败（更根本的故障）
        let rules = match vault.rules() {
            Ok(r) => r,
            Err(_) => {
                return LayerResult::Denied {
                    reason: DenyReason::RuleCorrupt,
                }
            }
        };
        if !all_keys_resolvable(req, vault) {
            return LayerResult::Denied {
                reason: DenyReason::MissingKeys,
            };
        }
        // 第 2 层：规则白名单
        let mut granted: HashSet<&str> = HashSet::new();
        for rule in &rules {
            if rule_matches(rule, &req.cwd, &req.command) {
                for k in &rule.keys {
                    granted.insert(k.as_str());
                }
            }
        }
        let keys: Vec<String> = req
            .keys
            .iter()
            .filter(|k| granted.contains(k.as_str()))
            .cloned()
            .collect();
        if keys.is_empty() {
            LayerResult::NeedsApproval
        } else {
            LayerResult::Allowed { keys }
        }
    }
}

/// 规则是否匹配 `(cwd, command)`（注入路径）：**capability=inject**（能力
/// 不互授，read 规则不授权注入）+ projectDir 祖先匹配（canonical 形态，
/// 相等或为前缀 + `/`）+ command glob（`*`/`?`，大小写敏感）。
pub fn rule_matches(rule: &Rule, canonical_cwd: &str, command: &str) -> bool {
    rule.capability == crate::model::RULE_CAPABILITY_INJECT
        && project_dir_matches(&rule.project_dir, canonical_cwd)
        && glob_match(&rule.command, command)
}

/// 读规则是否匹配 `(cwd, 条目名)`（值披露读路径，value-disclosure.md §4）：
/// **capability=read**（inject 规则不授权读）+ projectDir 祖先匹配（与
/// inject 同一套归一化/祖先匹配，WSL 侧两侧同函数）+ keys **精确包含**
/// 条目名（不做 key 通配，与 inject 的 keys 语义一致）。
pub fn read_rule_matches(rule: &Rule, canonical_cwd: &str, item_name: &str) -> bool {
    rule.capability == crate::model::RULE_CAPABILITY_READ
        && project_dir_matches(&rule.project_dir, canonical_cwd)
        && rule.keys.iter().any(|k| k == item_name)
}

/// 写动作（M2.97 写入门，write-gate.md §4/§5.2）：守护进程从
/// `ItemPutParams.id: Option<Uuid>` **权威派生**（None = create，Some =
/// update），不信任客户端自报。**无 Delete 变体**——delete 恒弹窗由协议
/// 保证（§3），根本不进规则匹配。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteAction {
    /// 新建（id=None）：keys 精确包含草稿名。
    Create,
    /// 整条替换（id=Some）：keys 同时包含存储名与草稿名（双向名约束）。
    Update,
}

/// 写规则是否匹配 `(cwd, action, 存储名?, 草稿名)`（写门路径，write-gate.md
/// §4）：**capability=write**（三能力两两不互授）+ projectDir 祖先匹配（与
/// inject/read 同一套归一化/祖先匹配，`wsl://` 规范形两侧同函数）+ 按动作：
///
/// - [`WriteAction::Create`]：actions 含 `create` 且 keys **精确包含草稿名**；
/// - [`WriteAction::Update`]：actions 含 `update` 且 keys **同时包含存储名
///   与草稿名**——改名不得「进出」授权名集合（堵改名逃生 / 改名植毒，§4）；
///   存储名未知（`None`）→ 不命中（fail-closed）。
///
/// 重名语义「名字即身份」：keys 按名匹配，覆盖全部同名条目（与读规则同构）。
pub fn write_rule_matches(
    rule: &Rule,
    canonical_cwd: &str,
    action: WriteAction,
    stored_name: Option<&str>,
    draft_name: &str,
) -> bool {
    if rule.capability != crate::model::RULE_CAPABILITY_WRITE {
        return false;
    }
    if !project_dir_matches(&rule.project_dir, canonical_cwd) {
        return false;
    }
    match action {
        WriteAction::Create => {
            rule.actions
                .iter()
                .any(|a| a == crate::model::RULE_ACTION_CREATE)
                && rule.keys.iter().any(|k| k == draft_name)
        }
        WriteAction::Update => {
            rule.actions
                .iter()
                .any(|a| a == crate::model::RULE_ACTION_UPDATE)
                && stored_name.is_some_and(|s| rule.keys.iter().any(|k| k == s))
                && rule.keys.iter().any(|k| k == draft_name)
        }
    }
}

/// projectDir 祖先匹配：`cwd` 等于 `project_dir`，或 `cwd` 是 `project_dir`
/// 的路径前缀（**按路径组件**比较——目录边界 `/a/b/cd` 不匹配 `/a/b/c`；
/// 分隔符随平台，Windows `C:\\a\\b` 与 `/` 写法均正确）。
///
/// 两侧先过 [`crate::path_ns::canonical_project_dir`] 归一化再比较（§7.4
/// 两侧同函数，幂等）：规则侧历史/同步入库的 verbatim 前缀形态
/// （`\\?\C:\…`）剥离为常规绝对路径；cwd 侧同样归一化——Windows 上
/// `fs::canonicalize` 产物本身即 verbatim 形态，未归一化将无法与规则侧命中
/// （守护进程边界已归一化时此步无副作用，属纵深防御：客户端自报 cwd 不得
/// 因写法变体绕过或漏配）。`wsl://<distro>/<rest>` 规范形保留原样。
/// 两侧均为 wsl:// 规范形时改用 wsl 形态匹配：大小写不敏感（NTFS 默认
/// 语义）、按 `/` 目录边界（cross-subsystem.md §7.4——distro 名保留原样
/// 但匹配不区分大小写，防伪造 cwd 大小写变体绕过或漏配）。
pub fn project_dir_matches(project_dir: &str, canonical_cwd: &str) -> bool {
    let dir_norm = crate::path_ns::canonical_project_dir(project_dir);
    let cwd_norm = crate::path_ns::canonical_project_dir(canonical_cwd);
    if crate::path_ns::is_wsl_canonical(&dir_norm) && crate::path_ns::is_wsl_canonical(&cwd_norm) {
        return crate::path_ns::wsl_ancestor_matches(&dir_norm, &cwd_norm);
    }
    let dir = std::path::Path::new(&dir_norm);
    let cwd = std::path::Path::new(&cwd_norm);
    cwd == dir || cwd.starts_with(dir)
}

/// 命令 glob 匹配（`*` = 任意长度、`?` = 单字符；其余字面量，大小写敏感）。
/// 双指针迭代实现（无递归/回溯爆炸）。
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut star_ti) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            star_ti = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 请求的 key 是否全部可在库中解析（不存在 → 第 1 层拒绝，不进审批：
/// 弹窗不为无法满足的请求打扰用户；不泄露库内有哪些 key——只反馈「无法满足」）。
fn all_keys_resolvable(req: &AuthzRequest, vault: &dyn RuleVault) -> bool {
    req.keys
        .iter()
        .all(|k| vault.secret_value(k).ok().flatten().is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use std::sync::mpsc;

    fn rule(project_dir: &str, command: &str, keys: &[&str]) -> Rule {
        Rule {
            id: Uuid::new_v4(),
            project_dir: project_dir.into(),
            name: "t".into(),
            command: command.into(),
            keys: keys.iter().map(|s| s.to_string()).collect(),
            capability: crate::model::RULE_CAPABILITY_INJECT.into(),
            actions: crate::model::default_rule_actions(),
            fingerprint: None,
            created: "2026-01-01T00:00:00.000000Z".into(),
        }
    }

    /// 假规则库（测试注入）。
    struct FakeVault {
        rules: Vec<Rule>,
        secrets: std::collections::HashMap<String, String>,
    }

    impl FakeVault {
        fn new(rules: Vec<Rule>, secrets: &[(&str, &str)]) -> FakeVault {
            FakeVault {
                rules,
                secrets: secrets
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    impl RuleVault for FakeVault {
        fn rules(&self) -> Result<Vec<Rule>> {
            Ok(self.rules.clone())
        }
        fn secret_value(&self, key_name: &str) -> Result<Option<String>> {
            Ok(self.secrets.get(key_name).cloned())
        }
    }

    /// 损坏规则库（解密失败 → fail-closed）。
    struct CorruptVault;

    impl RuleVault for CorruptVault {
        fn rules(&self) -> Result<Vec<Rule>> {
            Err(Error::Decrypt)
        }
        fn secret_value(&self, _key_name: &str) -> Result<Option<String>> {
            Ok(None)
        }
    }

    fn req(starter: &str, cwd: &str, command: &str, keys: &[&str]) -> AuthzRequest {
        AuthzRequest {
            starter: starter.into(),
            cwd: cwd.into(),
            command: command.into(),
            keys: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// 第 1 层短路：未知启动者 → 拒绝（不看规则）。
    #[test]
    fn layer1_denies_unknown_starter_before_rules() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        let r = gate.evaluate_layers(&req("unknown", "/proj", "npm publish", &["A"]), &vault);
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::UnknownStarter
            }
        );
    }

    /// 第 1 层：cwd 不可得 → 拒绝。
    #[test]
    fn layer1_denies_missing_cwd() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "", "npm publish", &["A"]), &vault),
            LayerResult::Denied {
                reason: DenyReason::NoCwd
            }
        );
    }

    /// 第 1 层：请求 key 无法解析 → 拒绝（不弹窗）。
    #[test]
    fn layer1_denies_unresolvable_keys() {
        let vault = FakeVault::new(vec![rule("/proj", "*", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["GHOST"]), &vault);
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::MissingKeys
            }
        );
    }

    /// 第 1 层：规则库损坏 → fail-closed 拒绝。
    #[test]
    fn layer1_denies_corrupt_rule_vault() {
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A"]),
            &CorruptVault,
        );
        assert_eq!(
            r,
            LayerResult::Denied {
                reason: DenyReason::RuleCorrupt
            }
        );
    }

    /// 第 2 层：规则命中 → 注入 = 规则 keys ∩ 请求 keys。
    #[test]
    fn layer2_allowed_intersects_rule_keys() {
        let vault = FakeVault::new(
            vec![rule("/proj", "npm *", &["A", "B"])],
            &[("A", "a"), ("B", "b")],
        );
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        // 请求 [A] → 注入 [A]（B 未请求，不注入——不泄漏未请求的值）
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["A"]), &vault);
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 请求 [A, B] → 注入 [A, B]
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A", "B"]),
            &vault,
        );
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into(), "B".into()]
            }
        );
    }

    /// 多规则命中取 keys 并集；请求的 key 未被任何规则授权 → 进第 3 层。
    #[test]
    fn layer2_union_across_rules_and_fallback() {
        let vault = FakeVault::new(
            vec![
                rule("/proj", "npm *", &["A"]),
                rule("/proj", "npm publish", &["B"]),
            ],
            &[("A", "a"), ("B", "b"), ("C", "c")],
        );
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        // 两条规则都命中 → 并集 {A, B}
        let r = gate.evaluate_layers(
            &req("/bin/zsh", "/proj", "npm publish", &["A", "B"]),
            &vault,
        );
        assert_eq!(
            r,
            LayerResult::Allowed {
                keys: vec!["A".into(), "B".into()]
            }
        );
        // 请求 [C]：无规则授权 → NeedsApproval
        let r = gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["C"]), &vault);
        assert_eq!(r, LayerResult::NeedsApproval);
    }

    /// 规则匹配矩阵：祖先/目录边界/glob。
    #[test]
    fn rule_matching_matrix() {
        // projectDir 祖先：相等 / 子目录 / 非子目录 / 前缀欺骗
        assert!(project_dir_matches("/a/b", "/a/b"));
        assert!(project_dir_matches("/a/b", "/a/b/c"));
        assert!(project_dir_matches("/a/b", "/a/b/c/d"));
        assert!(!project_dir_matches("/a/b", "/a/bc"));
        assert!(!project_dir_matches("/a/b", "/x/y"));
        assert!(!project_dir_matches("/a/b", "/a"));
        // 尾斜杠归一化
        assert!(project_dir_matches("/a/b/", "/a/b"));
        // command glob：精确 / 通配 / 不匹配
        assert!(glob_match("npm publish", "npm publish"));
        assert!(glob_match("npm *", "npm publish"));
        assert!(!glob_match("npm *", "npm")); // 空格为字面量（标准 glob 语义）
        assert!(glob_match("*publish", "npm publish"));
        assert!(glob_match("npm p?blish", "npm publish"));
        assert!(!glob_match("npm p?blish", "npm publish x"));
        assert!(!glob_match("npm *", "yarn publish"));
        assert!(!glob_match("npm publish", "npm publish --tag"));
        assert!(!glob_match("NPM *", "npm publish")); // 大小写敏感
                                                      // 组合
        let r = rule("/proj", "npm *", &["A"]);
        assert!(rule_matches(&r, "/proj/sub", "npm publish"));
        assert!(!rule_matches(&r, "/proj-other", "npm publish"));
        assert!(!rule_matches(&r, "/proj/sub", "yarn publish"));
    }

    /// 跨命名空间（cross-subsystem.md §7.4/§10）：规则录 `wsl://` 规范形，
    /// 伪造 UNC cwd 变体（大写 distro / 别名 / 尾斜杠）经守护进程侧
    /// [`crate::path_ns::canonical_project_dir`] 归一化后必须命中同一规则
    /// （不得绕过、也不得漏配）。
    #[test]
    fn wsl_namespace_rule_matches_normalized_cwd() {
        let vault = FakeVault::new(
            vec![rule("wsl://Debian/home/u/p", "*", &["A"])],
            &[("A", "a")],
        );
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\");
        assert_eq!(
            gate.evaluate_layers(&req("starter", &cwd, "npm publish", &["A"]), &vault),
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 目录边界外（p2）不得命中
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert_eq!(
            gate.evaluate_layers(&req("starter", &cwd2, "npm publish", &["A"]), &vault),
            LayerResult::NeedsApproval
        );
    }

    /// 符号链接目录：cwd 已 canonicalize → 与 canonical 规则目录匹配
    /// （真实 fs：临时目录 + symlink，canonicalize 后比较）。
    #[test]
    fn rule_matching_resolves_symlink_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real-proj");
        std::fs::create_dir_all(&real).unwrap();
        let link = dir.path().join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&real, &link).unwrap();
        let canonical_real = std::fs::canonicalize(&real).unwrap();
        let canonical_link = std::fs::canonicalize(&link).unwrap();
        // 规则绑定真实路径；cwd 经符号链接进入（canonical 后 = 真实路径）
        let r = rule(&canonical_real.to_string_lossy(), "*", &["A"]);
        assert!(rule_matches(
            &r,
            &canonical_link.join("sub").to_string_lossy(),
            "x"
        ));
        assert!(rule_matches(&r, &canonical_link.to_string_lossy(), "x"));
    }

    /// 审批决策三态 + 超时（PendingApprovals 注册表语义）。
    #[test]
    fn approval_decisions_allowed_denied_timeout() {
        let reg = Arc::new(PendingApprovals::new());
        let id = Uuid::new_v4();
        // 回传决策 → 唤醒等待者
        reg.register(id, Instant::now() + Duration::from_secs(10), "c1".into());
        // 挑战不符 → 忽略且**不清除**条目（防伪回传 DoS 掉真审批）
        assert!(!reg.resolve(id, ApprovalDecision::Allowed, "wrong"));
        assert_eq!(reg.pending_count(), 1);
        let h = std::thread::spawn({
            let reg = Arc::clone(&reg);
            move || {
                std::thread::sleep(Duration::from_millis(50));
                assert!(reg.resolve(id, ApprovalDecision::Allowed, "c1"));
            }
        });
        let d = reg.await_decision(id);
        h.join().unwrap();
        assert_eq!(d, ApprovalDecision::Allowed);
        assert_eq!(reg.pending_count(), 0, "消费后清理");

        // 超时 → 默认拒绝 + 清理
        reg.register(id, Instant::now() + Duration::from_millis(30), "c2".into());
        let d = reg.await_decision(id);
        assert_eq!(d, ApprovalDecision::Timeout);
        assert_eq!(reg.pending_count(), 0);

        // 伪造 requestId（未知/已清理）→ 忽略
        assert!(!reg.resolve(Uuid::new_v4(), ApprovalDecision::Allowed, "c2"));
    }

    /// LocalApprovalChannel：登记 + 广播 `authz.request` + 等待/超时。
    #[test]
    fn local_channel_broadcasts_and_waits() {
        let reg = Arc::new(PendingApprovals::new());
        let bus = Arc::new(EventBus::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        bus.subscribe(Arc::new(crate::bus::FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone());
        })));
        let ch = LocalApprovalChannel::new(Arc::clone(&reg), Arc::clone(&bus), Box::new(|| true));
        assert!(ch.available());
        let req = ApprovalRequest {
            request_id: Uuid::new_v4(),
            starter: "/bin/zsh".into(),
            project_dir: "/proj".into(),
            command: "npm publish".into(),
            keys: vec!["A".into()],
            challenge: "chal-xyz".into(),
            needs_unlock: false,
            kind: ApprovalKind::Inject,
            export_meta: None,
            fingerprint_mismatch: None,
        };
        // open：登记 + 广播（非阻塞）
        ch.open(&req, Instant::now() + Duration::from_secs(10));
        assert_eq!(reg.pending_count(), 1);
        assert_eq!(events.lock().unwrap().len(), 1);
        match &events.lock().unwrap()[0] {
            VaultEvent::AuthzRequest {
                request_id,
                starter,
                project_dir,
                command,
                keys,
                challenge,
                needs_unlock,
                kind,
                export_meta,
                fingerprint_mismatch,
            } => {
                assert_eq!(*request_id, req.request_id);
                assert_eq!(starter, "/bin/zsh");
                assert_eq!(project_dir, "/proj");
                assert_eq!(command, "npm publish");
                assert_eq!(keys, &vec!["A".to_string()]);
                // challenge 仅经事件通道下发（#78 方案 B）
                assert_eq!(challenge, "chal-xyz");
                // #67：常规（解锁态）审批不带 needs_unlock
                assert!(!needs_unlock);
                // M2.9 值披露：inject 审批不带导出元信息
                assert_eq!(*kind, ApprovalKind::Inject);
                assert!(export_meta.is_none());
                // M2.98：非失配注入审批不带指纹失配信息
                assert!(fingerprint_mismatch.is_none());
            }
            other => panic!("应广播 authz.request：{other:?}"),
        }
        // await：回传决策后返回
        let id = req.request_id;
        let h = std::thread::spawn({
            let reg = Arc::clone(&reg);
            move || {
                std::thread::sleep(Duration::from_millis(50));
                assert!(reg.resolve(id, ApprovalDecision::Allowed, "chal-xyz"));
            }
        });
        let d = ch.await_decision(req.request_id, Instant::now() + Duration::from_secs(10));
        h.join().unwrap();
        assert_eq!(d, ApprovalDecision::Allowed);
        assert_eq!(reg.pending_count(), 0);
    }

    /// 无界面 → available()=false（守护进程据此立即拒绝，不阻塞）。
    #[test]
    fn local_channel_unavailable_without_ui() {
        let ch = LocalApprovalChannel::new(
            Arc::new(PendingApprovals::new()),
            Arc::new(EventBus::new()),
            Box::new(|| false),
        );
        assert!(!ch.available());
    }

    /// 无界面审批通道的模拟（测试用；open/await 直接给结果）。
    struct NoopApproval;
    impl ApprovalChannel for NoopApproval {
        fn available(&self) -> bool {
            false
        }
        fn open(&self, _req: &ApprovalRequest, _expires_at: Instant) {}
        fn await_decision(&self, _id: Uuid, _expires_at: Instant) -> ApprovalDecision {
            ApprovalDecision::Denied
        }
    }

    /// 完整三层短路（NoopApproval 无界面）：规则命中 → Allowed；
    /// 未命中 → NeedsApproval（守护进程再判 available → 拒绝）。
    #[test]
    fn three_layer_short_circuit() {
        let vault = FakeVault::new(vec![rule("/proj", "npm *", &["A"])], &[("A", "a")]);
        let gate = AuthzGate::new(Arc::new(NoopApproval));
        // 第 1 层：未知启动者
        assert!(matches!(
            gate.evaluate_layers(&req("unknown", "/proj", "npm publish", &["A"]), &vault),
            LayerResult::Denied { .. }
        ));
        // 第 2 层：命中
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "/proj", "npm publish", &["A"]), &vault),
            LayerResult::Allowed {
                keys: vec!["A".into()]
            }
        );
        // 未命中 → 第 3 层
        assert_eq!(
            gate.evaluate_layers(&req("/bin/zsh", "/proj", "yarn publish", &["A"]), &vault),
            LayerResult::NeedsApproval
        );
    }

    #[test]
    fn glob_edge_cases() {
        assert!(glob_match("", ""));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "aXbYc"));
        assert!(!glob_match("a*b*c", "aXbYcZ"));
        assert!(glob_match("?", "x"));
        assert!(!glob_match("?", ""));
        assert!(glob_match("a?", "ab"));
        assert!(!glob_match("a?", "a"));
        // 全星号
        assert!(glob_match("***", "xyz"));
        // 长文本性能冒烟（双指针，无回溯爆炸）
        let long = "x".repeat(10_000);
        assert!(glob_match(&format!("{}*", "x".repeat(9_999)), &long));
        assert!(!glob_match(&format!("{}y", "x".repeat(9_999)), &long));
    }

    /// 广播 authz.request 不影响其它订阅者（emit 语义回归）。
    #[test]
    fn authz_request_emit_is_fire_and_forget() {
        let bus = Arc::new(EventBus::new());
        bus.subscribe(Arc::new(crate::bus::FnSink::new(|_| panic!("订阅者故障"))));
        let ch =
            LocalApprovalChannel::new(Arc::new(PendingApprovals::new()), bus, Box::new(|| true));
        ch.open(
            &ApprovalRequest {
                request_id: Uuid::new_v4(),
                starter: "s".into(),
                project_dir: "p".into(),
                command: "c".into(),
                keys: vec![],
                challenge: String::new(),
                needs_unlock: false,
                kind: ApprovalKind::Inject,
                export_meta: None,
                fingerprint_mismatch: None,
            },
            Instant::now() + Duration::from_secs(10),
        );
    }

    /// 并发冒烟：多个等待者各自拿到自己的决策（Condvar 正确唤醒）。
    #[test]
    fn concurrent_awaiters_resolve_independently() {
        let reg = Arc::new(PendingApprovals::new());
        let ids: Vec<Uuid> = (0..8).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            reg.register(*id, Instant::now() + Duration::from_secs(10), "c".into());
        }
        let (tx, rx) = mpsc::channel::<Uuid>();
        let mut handles = Vec::new();
        for id in ids.clone() {
            let reg = Arc::clone(&reg);
            let tx = tx.clone();
            handles.push(std::thread::spawn(move || {
                let d = reg.await_decision(id);
                assert_eq!(d, ApprovalDecision::Allowed);
                tx.send(id).unwrap();
            }));
        }
        drop(tx);
        std::thread::sleep(Duration::from_millis(50));
        for &id in &ids {
            assert!(reg.resolve(id, ApprovalDecision::Allowed, "c"));
        }
        let mut resolved: Vec<Uuid> = rx.iter().collect();
        resolved.sort();
        let mut expect = ids.clone();
        expect.sort();
        assert_eq!(resolved, expect);
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(reg.pending_count(), 0);
    }

    // -- M2.9 值披露（补充拍板 #20）：读规则匹配 + ApprovalKind ------------

    /// 读规则（capability=read）的 helper：command 恒空串（spec §4）。
    fn read_rule(project_dir: &str, keys: &[&str]) -> Rule {
        let mut r = rule(project_dir, "", keys);
        r.capability = crate::model::RULE_CAPABILITY_READ.into();
        r
    }

    /// 读规则匹配矩阵：capability 过滤 + projectDir 祖先 + keys 精确名。
    #[test]
    fn read_rule_matching_matrix() {
        let r = read_rule("/proj", &["A", "B"]);
        // 条目名精确包含 + cwd 祖先
        assert!(read_rule_matches(&r, "/proj", "A"));
        assert!(read_rule_matches(&r, "/proj/sub", "B"));
        assert!(!read_rule_matches(&r, "/proj", "C"), "keys 未包含 → 不命中");
        assert!(!read_rule_matches(&r, "/other", "A"), "cwd 不匹配 → 不命中");
        assert!(!read_rule_matches(&r, "/projc", "A"), "目录边界不匹配");
        // 能力不互授：inject 规则不授权读
        let inject = rule("/proj", "*", &["A"]);
        assert!(!read_rule_matches(&inject, "/proj", "A"));
        // read 规则不授权注入（inject 匹配路径按 capability 过滤）
        assert!(!rule_matches(&r, "/proj", "x"), "read 规则不得命中注入");
        // 带伪造 command 的 read 规则同样不得命中注入
        let mut rogue = r.clone();
        rogue.command = "npm *".into();
        assert!(!rule_matches(&rogue, "/proj", "npm publish"));
    }

    /// 读规则跨命名空间：`wsl://` 规范形规则命中归一化后的 WSL cwd
    /// （与 inject 同一套 project_dir_matches，两侧同函数）。
    #[test]
    fn read_rule_matches_wsl_normalized_cwd() {
        let r = read_rule("wsl://Debian/home/u/p", &["A"]);
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\sub");
        assert!(read_rule_matches(&r, &cwd, "A"));
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert!(!read_rule_matches(&r, &cwd2, "A"));
    }

    /// inject 规则（capability 缺省）照常命中注入路径（回归：legacy 规则
    /// 反序列化为 inject 后三层语义不变）。
    #[test]
    fn inject_rule_still_matches_after_capability_default() {
        let mut r = rule("/proj", "npm *", &["A"]);
        r.capability = crate::model::RULE_CAPABILITY_INJECT.into();
        assert!(rule_matches(&r, "/proj/sub", "npm publish"));
    }

    // -- M2.97 写入门（补充拍板 #24）：写规则匹配矩阵（write-gate.md §4/§10.1）-

    /// 写规则 helper：capability=write；command 恒空串（spec §4），keys =
    /// 条目名（精确，不做通配），actions = 写动作子集。
    fn write_rule(project_dir: &str, keys: &[&str], actions: &[&str]) -> Rule {
        let mut r = rule(project_dir, "", keys);
        r.capability = crate::model::RULE_CAPABILITY_WRITE.into();
        r.actions = actions.iter().map(|s| s.to_string()).collect();
        r
    }

    /// create：keys 精确包含草稿名 + projectDir 祖先匹配。
    #[test]
    fn write_rule_create_matches_draft_name() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Create,
            None,
            "config.ini"
        ));
        assert!(write_rule_matches(
            &r,
            "/proj/sub",
            WriteAction::Create,
            None,
            "config.ini"
        ));
        assert!(
            !write_rule_matches(&r, "/proj", WriteAction::Create, None, "other.ini"),
            "keys 未包含草稿名 → 不命中"
        );
        assert!(
            !write_rule_matches(&r, "/other", WriteAction::Create, None, "config.ini"),
            "cwd 不匹配 → 不命中"
        );
        assert!(
            !write_rule_matches(&r, "/projc", WriteAction::Create, None, "config.ini"),
            "目录边界不匹配"
        );
    }

    /// update：keys 同时包含存储名与草稿名（双向名约束）。
    #[test]
    fn write_rule_update_requires_both_names() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "config.ini"
        ));
        // 同目录改名（两名字都在授权集）：命中
        let multi = write_rule("/proj", &["old.ini", "new.ini"], &["update"]);
        assert!(write_rule_matches(
            &multi,
            "/proj",
            WriteAction::Update,
            Some("old.ini"),
            "new.ini"
        ));
    }

    /// 改名逃生：存储名不在 keys → 不命中（把授权条目改名出集合）。
    #[test]
    fn write_rule_rename_escape_denied() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("secret.ini"),
            "config.ini"
        ));
    }

    /// 改名植毒：草稿名不在 keys → 不命中（把非授权条目改名进集合）。
    #[test]
    fn write_rule_rename_poisoning_denied() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "poison.ini"
        ));
    }

    /// 重名语义「名字即身份」：规则按名覆盖全部同名条目（data-model.md
    /// 无名称唯一约束，重名允许）。匹配函数签名只收（存储名, 草稿名）
    /// 字符串、不收条目 id——同名条目无论 id 均命中同一规则，本用例把
    /// 该 API 形态钉住。
    #[test]
    fn write_rule_covers_all_same_named_items() {
        let r = write_rule("/proj", &["config.ini"], &["create", "update"]);
        assert!(write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("config.ini"),
            "config.ini"
        ));
    }

    /// actions 子集语义：create-only 不授 update，update-only 不授 create。
    #[test]
    fn write_rule_actions_are_per_action() {
        let create_only = write_rule("/proj", &["a.ini"], &["create"]);
        assert!(write_rule_matches(
            &create_only,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(!write_rule_matches(
            &create_only,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        let update_only = write_rule("/proj", &["a.ini"], &["update"]);
        assert!(!write_rule_matches(
            &update_only,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(write_rule_matches(
            &update_only,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
    }

    /// delete 不参与匹配（write-gate.md §3 恒弹窗）：即使规则 actions 防御性
    /// 含 "delete"，也不产生任何放行面——写门匹配只服务 create/update；
    /// `WriteAction` 无 Delete 变体（delete 根本不进规则匹配，daemon 直开弹窗）。
    #[test]
    fn delete_never_participates_in_rule_matching() {
        let r = write_rule("/proj", &["a.ini"], &["delete"]);
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(!write_rule_matches(
            &r,
            "/proj",
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        // actions 含 delete + create：delete 部分无效果，create 照常
        let mixed = write_rule("/proj", &["a.ini"], &["create", "delete"]);
        assert!(write_rule_matches(
            &mixed,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// 跨命名空间：`wsl://` 规范形规则命中归一化后的 WSL cwd（与 inject/read
    /// 同一套 project_dir_matches，两侧同函数）。
    #[test]
    fn write_rule_matches_wsl_normalized_cwd() {
        let r = write_rule("wsl://Debian/home/u/p", &["a.ini"], &["create", "update"]);
        let cwd = crate::path_ns::canonical_project_dir(r"\\wsl.localhost\DEBIAN\home\u\p\sub");
        assert!(write_rule_matches(
            &r,
            &cwd,
            WriteAction::Create,
            None,
            "a.ini"
        ));
        assert!(write_rule_matches(
            &r,
            &cwd,
            WriteAction::Update,
            Some("a.ini"),
            "a.ini"
        ));
        let cwd2 = crate::path_ns::canonical_project_dir(r"\\wsl$\Debian\home\u\p2");
        assert!(!write_rule_matches(
            &r,
            &cwd2,
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// 三能力两两不互授（双向）：write 不授权读/注入；read/inject 不授权写。
    #[test]
    fn write_capability_does_not_grant_read_or_inject() {
        let w = write_rule("/proj", &["A"], &["create", "update"]);
        // write 规则不命中注入 / 读路径
        assert!(!rule_matches(&w, "/proj", "npm publish"));
        assert!(!read_rule_matches(&w, "/proj", "A"));
        // read / inject 规则不命中写路径
        let rd = read_rule("/proj", &["A"]);
        assert!(!write_rule_matches(
            &rd,
            "/proj",
            WriteAction::Create,
            None,
            "A"
        ));
        assert!(!write_rule_matches(
            &rd,
            "/proj",
            WriteAction::Update,
            Some("A"),
            "A"
        ));
        let inj = rule("/proj", "*", &["A"]);
        assert!(!write_rule_matches(
            &inj,
            "/proj",
            WriteAction::Create,
            None,
            "A"
        ));
        // 带伪造 command 的 write 规则同样不得命中注入（capability 过滤在前）
        let mut rogue = w.clone();
        rogue.command = "npm *".into();
        assert!(!rule_matches(&rogue, "/proj", "npm publish"));
    }

    /// ApprovalKind 协议面序列化（serde camelCase 单词 → 小写）。
    #[test]
    fn approval_kind_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ApprovalKind::Inject).unwrap(),
            serde_json::json!("inject")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::Read).unwrap(),
            serde_json::json!("read")
        );
        assert_eq!(
            serde_json::to_value(ApprovalKind::Export).unwrap(),
            serde_json::json!("export")
        );
        // 规则管理审批门（补充拍板 #22）：kind=rule，加性变更不升协议版本
        assert_eq!(
            serde_json::to_value(ApprovalKind::Rule).unwrap(),
            serde_json::json!("rule")
        );
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("rule")).unwrap();
        assert_eq!(back, ApprovalKind::Rule);
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("read")).unwrap();
        assert_eq!(back, ApprovalKind::Read);
    }

    /// 写入门审批 kind（补充拍板 #24，write-gate.md §6）：kind=write，
    /// serde 往返，加性变更不升协议版本。
    #[test]
    fn approval_kind_write_serializes_lowercase() {
        assert_eq!(
            serde_json::to_value(ApprovalKind::Write).unwrap(),
            serde_json::json!("write")
        );
        let back: ApprovalKind = serde_json::from_value(serde_json::json!("write")).unwrap();
        assert_eq!(back, ApprovalKind::Write);
    }

    // -- 规则管理审批门（补充拍板 #22）：E2E 自动批准通道 --------------------

    fn auto_rule_req(kind: ApprovalKind) -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::new_v4(),
            starter: "/bin/zsh".into(),
            project_dir: "/proj".into(),
            command: "rule.add pub".into(),
            keys: vec!["NPM_TOKEN".into()],
            challenge: "chal".into(),
            needs_unlock: false,
            kind,
            export_meta: None,
            fingerprint_mismatch: None,
        }
    }

    /// env 门控开启时仅规则审批立即 Allowed：不广播（无 UI 参与）、
    /// 等待者即刻拿到决策；inject/read/export 不受影响（走内层通道）。
    #[test]
    fn auto_channel_allows_rule_kind_immediately() {
        let reg = Arc::new(PendingApprovals::new());
        let bus = Arc::new(EventBus::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        bus.subscribe(Arc::new(crate::bus::FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone());
        })));
        let inner =
            LocalApprovalChannel::new(Arc::clone(&reg), Arc::clone(&bus), Box::new(|| false));
        let ch = AutoApproveChannel::with_rule_enabled(Arc::new(inner), Arc::clone(&reg), true);
        // auto_approves 仅对 rule 为真；available 语义不因 E2E 门改变（无 UI）
        assert!(ch.auto_approves(ApprovalKind::Rule));
        assert!(!ch.auto_approves(ApprovalKind::Inject));
        assert!(!ch.auto_approves(ApprovalKind::Read));
        assert!(
            !ch.available(),
            "无 UI 时 available 仍为 false（inject 照旧 fail-closed）"
        );
        // open(rule)：登记 + 立即 Allowed，不广播 authz.request
        let req = auto_rule_req(ApprovalKind::Rule);
        ch.open(&req, Instant::now() + Duration::from_secs(10));
        assert_eq!(
            events.lock().unwrap().len(),
            0,
            "自动批准不广播（无 UI 参与）"
        );
        let d = ch.await_decision(req.request_id, Instant::now() + Duration::from_secs(10));
        assert_eq!(d, ApprovalDecision::Allowed);
        assert_eq!(reg.pending_count(), 0, "消费后清理");
    }

    /// env 门控关闭（生产缺省）：一切 kind 都走内层通道（auto_approves 恒 false）。
    #[test]
    fn auto_channel_disabled_delegates_to_inner() {
        let reg = Arc::new(PendingApprovals::new());
        let bus = Arc::new(EventBus::new());
        let inner =
            LocalApprovalChannel::new(Arc::clone(&reg), Arc::clone(&bus), Box::new(|| true));
        let mut ch = AutoApproveChannel::with_rule_enabled(Arc::new(inner), Arc::clone(&reg), true);
        ch.set_rule_enabled_for_tests(false);
        assert!(!ch.auto_approves(ApprovalKind::Rule));
        // open(rule) 走内层：广播 authz.request（桌面弹窗语义不变）
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        bus.subscribe(Arc::new(crate::bus::FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone());
        })));
        ch.open(
            &auto_rule_req(ApprovalKind::Rule),
            Instant::now() + Duration::from_secs(10),
        );
        assert_eq!(events.lock().unwrap().len(), 1, "未启用时照常广播");
        assert_eq!(reg.pending_count(), 1, "等待桌面回传");
    }

    /// env 读取：LIGHTKEY_E2E_AUTO_APPROVE=rule → 开启（daemon 启动时读一次）。
    /// 测试环境不设置该变量 → 关闭（不与并行测试竞争 env）。
    #[test]
    fn auto_channel_env_probe() {
        assert_eq!(
            std::env::var(AutoApproveChannel::ENV).ok().as_deref(),
            None,
            "测试进程不得携带 E2E 自动批准变量（否则用例互相污染）"
        );
        assert!(!AutoApproveChannel::env_rule_enabled());
    }

    /// 审批请求携带 kind + export 数据包元信息（export 弹窗展示规模用）。
    #[test]
    fn approval_request_carries_kind_and_export_meta() {
        let areq = ApprovalRequest {
            request_id: Uuid::new_v4(),
            starter: "/bin/zsh".into(),
            project_dir: "/proj".into(),
            command: "item.export".into(),
            keys: vec!["合同.pdf".into()],
            challenge: "chal".into(),
            needs_unlock: false,
            kind: ApprovalKind::Export,
            export_meta: Some(ExportMeta {
                name: "合同.pdf".into(),
                mime: "application/pdf".into(),
                size: 1024,
            }),
            fingerprint_mismatch: None,
        };
        assert_eq!(areq.kind, ApprovalKind::Export);
        assert_eq!(areq.export_meta.as_ref().unwrap().size, 1024);
        // 常规注入审批不带 export 元信息
        let inject_req = ApprovalRequest {
            kind: ApprovalKind::Inject,
            export_meta: None,
            ..areq.clone()
        };
        assert!(inject_req.export_meta.is_none());
    }

    // -- M2.98 规则程序指纹（补充拍板 #25）：未绑定匹配路径零变化回归 ---------

    /// 给规则绑定一个任意指纹，`rule_matches` / `read_rule_matches` /
    /// `write_rule_matches` 的结果必须与未绑定（None）完全一致——指纹是
    /// **正交追加门**，不在三条匹配路径上内联；T2 daemon 装配 `fingerprint_matches`
    /// 作为追加裁决。fingerprint=None = 现状语义（identity-binding.md §4「匹配
    /// 函数行为零变化」）。
    #[test]
    fn fingerprint_does_not_change_base_matcher_behavior() {
        use crate::model::ProgramFingerprint;

        // 注：三分支的匹配结果与有无指纹无关，恒由 capability/cwd/keys 决定；
        // 此处钉住「绑定 vs 未绑定」结果一致，防未来误把指纹塞进 matcher 内联
        // 而改变未绑定路径行为。
        let fp_some = Some(ProgramFingerprint {
            exe_path: "/usr/bin/node".into(),
            sha256: "a".repeat(64),
            size: 100,
        });

        // inject 规则
        let mut inj = rule("/proj", "npm *", &["A"]);
        let inj_unbound = rule("/proj", "npm *", &["A"]);
        inj.fingerprint = fp_some.clone();
        assert_eq!(
            rule_matches(&inj, "/proj/sub", "npm publish"),
            rule_matches(&inj_unbound, "/proj/sub", "npm publish"),
        );
        assert!(rule_matches(&inj_unbound, "/proj/sub", "npm publish"));

        // read 规则
        let mut rd = read_rule("/proj", &["A"]);
        let rd_unbound = read_rule("/proj", &["A"]);
        rd.fingerprint = fp_some.clone();
        assert_eq!(
            read_rule_matches(&rd, "/proj", "A"),
            read_rule_matches(&rd_unbound, "/proj", "A"),
        );
        assert!(read_rule_matches(&rd_unbound, "/proj", "A"));

        // write 规则（create）
        let mut wr = write_rule("/proj", &["a.ini"], &["create", "update"]);
        let wr_unbound = write_rule("/proj", &["a.ini"], &["create", "update"]);
        wr.fingerprint = fp_some;
        assert_eq!(
            write_rule_matches(&wr, "/proj", WriteAction::Create, None, "a.ini"),
            write_rule_matches(&wr_unbound, "/proj", WriteAction::Create, None, "a.ini"),
        );
        assert!(write_rule_matches(
            &wr_unbound,
            "/proj",
            WriteAction::Create,
            None,
            "a.ini"
        ));
    }

    /// 绑定规则与未绑定规则占据同一片授权空间，指纹门不改变未命中语义：
    /// 匹配器继续负责 capability/cwd/keys，未绑定的始终未命中时与现状一致。
    #[test]
    fn unbound_rule_matchers_unchanged_for_miss_cases() {
        // read 规则未命中 cases（现状语义原样）
        let rd = read_rule("/proj", &["A"]);
        assert!(!read_rule_matches(&rd, "/proj", "B"));
        assert!(!read_rule_matches(&rd, "/other", "A"));
        // inject 未命中：cwd 不匹配 / command glob 不匹配
        let inj = rule("/proj", "npm *", &["A"]);
        assert!(!rule_matches(&inj, "/other", "npm publish"));
        assert!(!rule_matches(&inj, "/proj", "yarn publish"));
    }
}
