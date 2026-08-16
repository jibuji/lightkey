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

/// 审批请求负载（`authz.request` 事件与弹窗展示用；keys 仅 key 名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: Uuid,
    pub starter: String,
    pub project_dir: String,
    pub command: String,
    pub keys: Vec<String>,
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
    /// 是否有界面可能响应审批（桌面壳已订阅推送连接）。`false` →
    /// fail-closed 立即拒绝，不登记、不阻塞（authorization-gate.md §7）。
    fn available(&self) -> bool;
    /// 登记待审批 + 广播 `authz.request`（非阻塞；守护进程命令锁内调用）。
    fn open(&self, req: &ApprovalRequest, expires_at: Instant);
    /// 等待决策（守护进程命令锁外调用；最多等到 `expires_at`，超时默认拒绝）。
    fn await_decision(&self, request_id: Uuid, expires_at: Instant) -> ApprovalDecision;
}

/// 待审批条目（`expires_at` 到期即清理；决策槽供 `approval.result` 写入）。
#[derive(Debug, Clone, Copy)]
struct PendingApproval {
    decision: Option<ApprovalDecision>,
    expires_at: Instant,
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

    /// 登记待审批（幂等：重复登记刷新到期时刻与决策槽）。
    pub fn register(&self, request_id: Uuid, expires_at: Instant) {
        self.inner.lock().unwrap().insert(
            request_id,
            PendingApproval {
                decision: None,
                expires_at,
            },
        );
    }

    /// 回传决策（`approval.result`）：条目存在且未到期 → 写入并唤醒等待者；
    /// 未知/已超时（伪造 requestId）→ 忽略（返回 false）。
    pub fn resolve(&self, request_id: Uuid, decision: ApprovalDecision) -> bool {
        let mut map = self.inner.lock().unwrap();
        let expired = map
            .get(&request_id)
            .map(|p| Instant::now() >= p.expires_at)
            .unwrap_or(true);
        if expired {
            map.remove(&request_id);
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
        self.approvals.register(req.request_id, expires_at);
        // 广播 `authz.request`（通知 D 层弹窗；无密钥值）
        self.bus.emit(&VaultEvent::AuthzRequest {
            request_id: req.request_id,
            starter: req.starter.clone(),
            project_dir: req.project_dir.clone(),
            command: req.command.clone(),
            keys: req.keys.clone(),
        });
    }

    fn await_decision(&self, request_id: Uuid, expires_at: Instant) -> ApprovalDecision {
        // 到期时刻以登记值为准（`expires_at` 参数为远程通道语义预留）
        let _ = expires_at;
        self.approvals.await_decision(request_id)
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

/// 规则是否匹配 `(cwd, command)`：projectDir 祖先匹配（canonical 形态，
/// 相等或为前缀 + `/`）+ command glob（`*`/`?`，大小写敏感）。
pub fn rule_matches(rule: &Rule, canonical_cwd: &str, command: &str) -> bool {
    project_dir_matches(&rule.project_dir, canonical_cwd) && glob_match(&rule.command, command)
}

/// projectDir 祖先匹配：`cwd` 等于 `project_dir`，或 `cwd` 以
/// `project_dir + "/"` 开头（目录边界，`/a/b/cd` 不匹配 `/a/b/c`）。
pub fn project_dir_matches(project_dir: &str, canonical_cwd: &str) -> bool {
    let dir = project_dir.trim_end_matches('/');
    let cwd = canonical_cwd.trim_end_matches('/');
    if cwd == dir {
        return true;
    }
    cwd.starts_with(&format!("{dir}/"))
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
        reg.register(id, Instant::now() + Duration::from_secs(10));
        let h = std::thread::spawn({
            let reg = Arc::clone(&reg);
            move || {
                std::thread::sleep(Duration::from_millis(50));
                assert!(reg.resolve(id, ApprovalDecision::Allowed));
            }
        });
        let d = reg.await_decision(id);
        h.join().unwrap();
        assert_eq!(d, ApprovalDecision::Allowed);
        assert_eq!(reg.pending_count(), 0, "消费后清理");

        // 超时 → 默认拒绝 + 清理
        reg.register(id, Instant::now() + Duration::from_millis(30));
        let d = reg.await_decision(id);
        assert_eq!(d, ApprovalDecision::Timeout);
        assert_eq!(reg.pending_count(), 0);

        // 伪造 requestId（未知/已清理）→ 忽略
        assert!(!reg.resolve(Uuid::new_v4(), ApprovalDecision::Allowed));
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
            } => {
                assert_eq!(*request_id, req.request_id);
                assert_eq!(starter, "/bin/zsh");
                assert_eq!(project_dir, "/proj");
                assert_eq!(command, "npm publish");
                assert_eq!(keys, &vec!["A".to_string()]);
            }
            other => panic!("应广播 authz.request：{other:?}"),
        }
        // await：回传决策后返回
        let id = req.request_id;
        let h = std::thread::spawn({
            let reg = Arc::clone(&reg);
            move || {
                std::thread::sleep(Duration::from_millis(50));
                assert!(reg.resolve(id, ApprovalDecision::Allowed));
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
            reg.register(*id, Instant::now() + Duration::from_secs(10));
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
            assert!(reg.resolve(id, ApprovalDecision::Allowed));
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
}
