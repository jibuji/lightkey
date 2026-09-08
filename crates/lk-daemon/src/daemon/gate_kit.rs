//! gate-kit（issue #148）：四个授权门模块（authz / disclosure / rules /
//! write）各自重抄的「五件套」中可下沉部分的唯一出处——纯下沉，零行为变更
//!（issue #167 起结果类型升为**分层裁决结果**，见 [`GateBegin`] /
//! [`DeferredOutcome`]）。
//!
//! - [`GateBegin`] / [`GateDeny`]：begin 阶段**分层裁决结果**（拒绝(reason) /
//!   放行·直返(负载) / 未命中需审批；issue #167）；
//! - [`ApprovalRegistry`] / [`ApprovalEntry`] / [`GateEntry`] / [`GateKind`]：
//!   **守护进程侧审批注册表**（拍板 #28 候选 2，issue #166：取代 core
//!   `PendingApprovals` + daemon `PendingGates` 双表——单表承载质询值 /
//!   到期时刻 / 决策槽 + needs_unlock / 审批工作区 / 门负载；生命周期
//!   三拍：登记 → 裁决写 → finalize 单点消费移除）；审批解锁辅助
//!   （needs_unlock 判定 / 临时 vault 存取）表无关，未来任何门带
//!   needs_unlock 自动被看见（#67/#23 类特性不再逐门特判）；
//! - [`Daemon::open_gate_approval`]：审批请求（id / challenge / 超时）单点
//!   铸造 + 注册表登记 + `authz.request` 广播（challenge 一次性等不变量
//!   只有一处实现，#78）+ E2E 规则自动批准分支（#22 折入 daemon）；
//! - [`Daemon::audit_gate`] + [`ActingVault`] + [`Daemon::with_acting_vault`]：
//!   四门合一的审计辅助——事件字段由门提供，K_audit 按「本次执行所用
//!   vault」签名（执行/审计入口统一收 ActingVault，issue #150 起无
//!   `_from` 变体对）；
//! - [`ApprovalWorkspace`]：审批工作区（issue #150）——临时解锁材料与
//!   单次裁决状态的条目内一等对象；「单次即毁 / 不签令牌 / 不置共享
//!   vault / 指纹裁决单发」不变量的**单点出处**（类型文档即权威）；
//! - 参数解析辅助（[`parse_gate_params`] / [`invalid_params`]）；
//! - [`DeferredOutcome`]：finalize 阶段**分层结果**（决策结局 vs 执行结果
//!   两层 + RePended；issue #167）。
//!
//! 预检（precheck）/ begin / finalize 由各门以**静态门声明**承载（issue
//! #167，`router::GateDecl`），锁编排与字节收线收敛于 router.rs 的通用
//! deferred 编排器。

use std::collections::HashMap;
use std::sync::Condvar;
use std::time::{Duration, Instant};

use super::disclosure::PendingDisclosure;
use super::rules::PendingRuleChange;
use super::write::PendingWrite;
use super::*;

/// begin 阶段分层裁决结果（issue #167 / 拍板 #28 候选 3）：裁决本体的
/// 三态 = 拒绝(reason) / 放行·直返(负载) / 未命中需审批；`Final` 亦承载
/// **非裁决**的协议层直返（参数解析失败 / `item.not_found` / 方法未知）。
///
/// 关键分层：**拒绝的响应字节不在此决定**——`Deny(reason)` 的 reason 是
/// 一等数据，字节由门声明的渲染器按 (门 × 锁态/会话态) 唯一渲染（同一
/// reason 跨门跨锁态字节不同：解锁态 inject=`ok{no_ui}` vs disclosure=
/// `authz.denied`(-32017)，不得压平）。而「锁态 headless inject =
/// `session.invalid`」是**会话前置失败**（执行层，编排器预检 / begin 锁态
/// 分支直返 `Final(session.invalid)`），不是裁决拒绝——这正是两层结果
/// 防止 6 类 spec 钉死的 fail-closed 码被压平的机制（§1.6）。
#[derive(Debug, Clone)]
pub(crate) enum GateBegin {
    /// 裁决拒绝：reason 一等数据，字节交门声明渲染器（唯一决定点）。
    Deny(GateDeny),
    /// 放行 / 协议层直返（payload = 已渲染的响应行：规则命中执行结果 /
    /// desktop 豁免执行结果 / 解析错误 / 会话前置失败 `session.invalid`）。
    Final(String),
    /// 未命中需审批（登记 + 广播已完成；等待移出命令锁，G1）。
    Pending { request_id: uuid::Uuid },
}

/// 跨门拒绝原因（issue #167）：随分层裁决结果流动的一等数据。**不含字节**——
/// 字节由各门渲染器按 (门 × 锁态/会话态) 决定；同一 reason 跨门跨锁态
/// 字节不同是 spec 钉死的安全不变量（§1.6 六类 fail-closed 码）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateDeny {
    /// 启动者未知（第 1 层 fail-closed，不弹窗）。
    UnknownStarter,
    /// 对端 cwd 不可得（规则按项目目录绑定）。
    NoCwd,
    /// 无审批界面（headless；含锁态一体化二次审批界面离场）。
    NoUi,
    /// 决策拒绝 / 待审条目消费竞态的保守拒绝（finalize 决策结局）。
    Rejected,
    /// 审批超时（默认拒绝；finalize 决策结局）。
    Timeout,
    /// 第 1/2 层裁决拒绝（核心 [`DenyReason`] 透传：missing_keys /
    /// rule_corrupt / 层内 unknown_starter 等；渲染按 `as_str`）。
    Layer(DenyReason),
}

impl GateDeny {
    /// CLI/弹窗文案映射（与核心 [`DenyReason::as_str`] 同词表）。
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            GateDeny::UnknownStarter => "unknown_starter",
            GateDeny::NoCwd => "no_cwd",
            GateDeny::NoUi => "no_ui",
            GateDeny::Rejected => "rejected",
            GateDeny::Timeout => "timeout",
            GateDeny::Layer(r) => r.as_str(),
        }
    }
}

/// finalize 阶段分层结果（issue #167 / 拍板 #28 候选 3，实现以规格 §3
/// 评审修订为准）：**决策结局**与**执行结果**分两层建模——
///
/// - 决策结局：`Denied`（deny / timeout / 条目消费竞态 → 统一拒绝尾，
///   字节交门声明渲染器）；
/// - 执行结果：`Executed`（决策已定后的执行成功，payload = 响应行）/
///   `SessionInvalid`（决策已 Allowed 而 vault 已锁 / 解析失败——**执行
///   失败而非 Denied 决策**，跨门统一 `session.invalid`）/ `ExecutionDenied`
///   （TOCTOU 重验失效、审批工作区缺失、二次审批界面离场等执行层保守
///   拒绝——字节走本门拒绝尾，但**不是**用户决策）；
/// - `RePended`：锁态一体化指纹补裁决失配转二次审批（issue #140；仅
///   `rependable` 门声明可达，编排器消费声明、违例 release fail-closed）。
#[derive(Debug, Clone)]
pub(crate) enum DeferredOutcome {
    /// 执行成功（payload = 执行结果响应行）。
    Executed(String),
    /// 执行失败：锁态/会话材料不可用 → 统一 `session.invalid`。
    SessionInvalid,
    /// 执行失败：保守拒绝（TOCTOU 重验失效 / 工作区缺失 / 二次审批界面
    /// 离场）→ 字节走本门拒绝尾。
    ExecutionDenied(GateDeny),
    /// 决策结局：统一拒绝尾（deny / timeout / 条目消费竞态）。
    Denied(GateDeny),
    /// 转二次审批（回到锁外等待；RePended 循环内建于编排器）。
    RePended { request_id: uuid::Uuid },
}

/// 审批工作区（issue #150）：注册表条目内的**一等对象**——临时解锁材料与
/// 单次裁决状态的唯一承载。正常路径恒不存在（条目字段恒 `None`），仅锁定态
/// 一体化解锁路径（#67 inject / #23 读通道）由 `approval.result`（正确主
/// 密码 + allowed）填充。
///
/// 生命周期与条目**严格一致**：工作区只存在于 [`ApprovalEntry`] 内，finalize
/// 消费即随条目销毁；超时竞态（条目已被 finalize 取走）下
/// `store_workspace_and_resolve` 失败、工作区随调用方作用域整体 drop。由此
/// **由构造与生命周期承载**的不变量（取代既往散布各门 finalize / 审批回传
/// 路径的注释纪律）：
///
/// - **单次即毁**：vault 字段私有、只出不进借用（[`Self::vault`]），
///   所有权无法离开工作区——不存在把临时 vault 移入 `shared.vault`（共享
///   解锁态）的代码路径；
/// - **不签发会话令牌 / 不写 session.token**：会话签发代码对工作区无任何
///   访问面（无持有主密码、无 vault 所有权可移交）；
/// - **指纹裁决单发**（issue #140）：裁决一次性状态随工作区走
///   （[`Self::fingerprint_adjudicated`] / [`Self::mark_fingerprint_adjudicated`]），
///   二次审批条目携带已裁决工作区——防「裁决 → 审批 → 裁决」死循环由
///   结构承载，#140 类竞态不可复发。
pub(crate) struct ApprovalWorkspace {
    /// 临时解锁 vault（私有：仅借出引用，无所有权出口）。
    vault: UnlockedVault,
    /// 指纹裁决单发状态（issue #140）：false = 本次审批尚未做过指纹裁决
    /// （锁定态一体化 begin 无法裁决）；true = 已裁决（解锁态 begin 侧或
    /// 二次审批条目），finalize 不得重复裁决。
    fp_adjudicated: bool,
}

impl ApprovalWorkspace {
    /// 由临时解锁产物构造（`approval.result` 解锁成功路径，session.rs）。
    /// 初始未裁决（锁定态一体化 begin 无法预裁决）。
    pub(crate) fn new(vault: UnlockedVault) -> Self {
        Self {
            vault,
            fp_adjudicated: false,
        }
    }

    /// 临时 vault 借用（K_audit / 规则 / 密文在此内存态可用；finalize 在
    /// 其上执行裁决、读值与审计签名）。
    pub(crate) fn vault(&self) -> &UnlockedVault {
        &self.vault
    }

    /// 指纹裁决是否已执行（单发状态读取）。
    pub(crate) fn fingerprint_adjudicated(&self) -> bool {
        self.fp_adjudicated
    }

    /// 标记指纹裁决已执行（转二次审批时随工作区移入新条目——新条目的
    /// finalize 不再裁决）。
    pub(crate) fn mark_fingerprint_adjudicated(&mut self) {
        self.fp_adjudicated = true;
    }
}

/// begin 侧待审批负载（各门在命令锁内构造，随后经
/// [`Daemon::open_gate_approval`] 单点铸造质询值/到期后登记进审批注册表）。
/// needs_unlock 与审批工作区是条目级一等字段（issue #148/#150）：审批解锁
/// 辅助表无关。
pub(crate) struct GateEntry {
    /// 锁定态一体化标志（#67 inject / #23 读通道）：审批需先临时解锁；
    /// `authz.request` 帧的 `needsUnlock` 与本值同源（单点铸造保证）。
    /// 规则门/写门恒 false——由 [`GateEntry::approval`] 构造器与各门流程
    /// 声明（`GateDecl::unlock_supported`，issue #167）显式承载。
    pub needs_unlock: bool,
    /// 审批工作区（issue #150，见 [`ApprovalWorkspace`] 类型文档——不变量
    /// 「单次即毁 / 不签令牌 / 不置共享 vault」的单点出处）。正常路径恒
    /// `None`，仅一体化解锁路径由审批回传填充；二次审批条目（#140）由
    /// finalize 转办时随条目携带。
    pub workspace: Option<ApprovalWorkspace>,
    /// 门负载（各门 begin 期已解析的产物）。
    pub kind: GateKind,
}

impl GateEntry {
    /// 常规审批条目（解锁态；**显式声明无需一体化解锁**——规则门/写门等）。
    pub(crate) fn approval(kind: GateKind) -> Self {
        Self {
            needs_unlock: false,
            workspace: None,
            kind,
        }
    }

    /// 一体化解锁审批条目（锁定态 #67/#23：审批回传以主密码临时解锁后
    /// 由 [`ApprovalRegistry::store_workspace_and_resolve`] 填充工作区）。
    pub(crate) fn unified_unlock(kind: GateKind) -> Self {
        Self {
            needs_unlock: true,
            workspace: None,
            kind,
        }
    }
}

/// 统一注册表条目的门负载（issue #148：payload = 门枚举）。
pub(crate) enum GateKind {
    /// 授权判定第 3 层待办（daemon/authz.rs）。
    Authz(PendingAuthz),
    /// 值披露第 3 层待办（daemon/disclosure.rs）。
    Disclosure(PendingDisclosure),
    /// 规则管理审批门待办（daemon/rules.rs）。
    Rule(PendingRuleChange),
    /// 条目写入审批门待办（daemon/write.rs）。
    Write(PendingWrite),
}

/// 审批注册表行（key = 请求 id，由外层 map 承担）：门负载
/// （[`GateEntry`]）+ 审批三要素（决策槽 / 到期时刻 / 一次性质询值）。
/// 生命周期三拍（拍板 #28 候选 2）——登记（begin）→ 裁决写
/// （`approval.result` 回传写决策与工作区）→ 收尾节点**唯一消费移除**
/// （finalize 的 [`ApprovalRegistry::remove`]）；`await_decision` 只读
/// 不移除，`resolve` 按过期/未知拒绝写（迟到回传不得回翻已超时的等待
/// 结果）。
pub(crate) struct ApprovalEntry {
    /// 决策槽（`None` = 未裁决；写决策的唯一入口是审批回传路径的
    /// `resolve` / `store_workspace_and_resolve`）。
    pub(crate) decision: Option<ApprovalDecision>,
    /// 到期时刻（登记值权威；到期 → 等待者收 `Timeout`、回传按过期拒绝写）。
    pub(crate) expires_at: Instant,
    /// 一次性质询值（#78 方案 B：仅随 `authz.request` 事件帧投桌面订阅者，
    /// 回传必须原样带回；比较用普通等值判定——注册表为进程内共享内存，
    /// 无逐字节侧信道面）。
    pub(crate) challenge: String,
    /// 锁定态一体化标志（同 [`GateEntry::needs_unlock`]，登记时随门负载
    /// 入表——单表后不再有第二份拷贝）。
    pub(crate) needs_unlock: bool,
    /// 审批工作区（issue #150，见 [`ApprovalWorkspace`] 类型文档）。
    pub(crate) workspace: Option<ApprovalWorkspace>,
    /// 门负载（各门 begin 期已解析的产物）。
    pub(crate) kind: GateKind,
}

/// 守护进程侧**审批注册表**（拍板 #28 候选 2「审批注册表合一」，issue
/// #166）：取代此前跨 core/daemon 的两张表（core `PendingApprovals` 的
/// challenge/decision/expires + condvar await 与 daemon `PendingGates` 的
/// needs_unlock/workspace/kind）——一次审批只登记进这一张表。
///
/// 跨线程共享：命令线程登记（begin，命令锁内）/ 锁外等待
/// （[`Self::await_decision`]，只读），`approval.result` 回传线程写决策与
/// 工作区（[`Self::resolve`] / [`Self::store_workspace_and_resolve`]），
/// finalize 单点消费移除。锁为注册表内部短锁（G1：等待期间不持命令锁，
/// 等待以 condvar 挂起、不持注册表锁阻塞写入方）。
///
/// 类型本身 `pub`（`SharedDaemon.approvals` 字段的可达性要求；方法面保持
/// crate 内）。
#[derive(Default)]
pub struct ApprovalRegistry {
    inner: Mutex<HashMap<uuid::Uuid, ApprovalEntry>>,
    condvar: Condvar,
}

impl ApprovalRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 三拍之一·登记（begin 阶段，命令锁内）：门负载条目 + 单点铸造的
    /// 质询值与到期时刻入表（幂等：重复登记整条覆盖）。
    pub(crate) fn insert(
        &self,
        request_id: uuid::Uuid,
        gate: GateEntry,
        expires_at: Instant,
        challenge: String,
    ) {
        self.inner.lock().unwrap().insert(
            request_id,
            ApprovalEntry {
                decision: None,
                expires_at,
                challenge,
                needs_unlock: gate.needs_unlock,
                workspace: gate.workspace,
                kind: gate.kind,
            },
        );
    }

    /// 三拍之二·裁决写（`approval.result` 回传，非一体化路径）：条目存在
    /// 且未到期**且质询值匹配** → 写入决策并唤醒等待者。
    ///
    /// - 伪造 requestId（未知）或条目已过期 → **拒绝写**（return false →
    ///   桌面 `accepted=false` + 失败提交 Denied 审计）；条目**不移除**——
    ///   迟到回传不得回翻等待侧已得的 Timeout，移除归 finalize；
    /// - 质询不符（#78：无广播帧则拿不到 challenge）→ **不移除**条目，
    ///   防止伪回传把真用户的待审批请求打掉（拒绝 DoS），仅本次忽略。
    pub(crate) fn resolve(
        &self,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
        challenge: &str,
    ) -> bool {
        let mut map = self.inner.lock().unwrap();
        write_decision_locked(&mut map, &self.condvar, request_id, decision, challenge)
    }

    /// 一体化解锁路径的裁决写（`approval.result` allowed + masterPassword，
    /// session.rs）：**同一临界区**内先存工作区、再写决策——不产生错误
    /// 结果（spec §2；白费临时解锁与 `vault.unlock` 审计在超时竞态下仍会
    /// 发生——解锁发生在临界区之前，与折入前行为等价，非本次消除目标）。
    ///
    /// - 条目不在册（已被 finalize 消费的超时竞态）→ false，工作区随调用
    ///   方作用域整体 drop（生命周期与条目严格一致）；
    /// - 条目已带工作区（#140 二次审批条目）时**替换解锁材料、保留单次
    ///   裁决状态**：指纹单发状态属于条目侧裁决流程而非某一份解锁材料
    ///   ——重解锁不得重置「已裁决」标记，否则失配二次审批将再次裁决、
    ///   再次失配，形成裁决死循环（#140 类竞态由结构排除）；
    /// - 工作区存储后的决策写入语义与 [`Self::resolve`] 一致（过期/质询
    ///   不符 → 拒绝写，条目保留）。
    pub(crate) fn store_workspace_and_resolve(
        &self,
        request_id: uuid::Uuid,
        mut ws: ApprovalWorkspace,
        decision: ApprovalDecision,
        challenge: &str,
    ) -> bool {
        let mut map = self.inner.lock().unwrap();
        match map.get_mut(&request_id) {
            Some(entry) => {
                if let Some(prev) = entry.workspace.take() {
                    if prev.fingerprint_adjudicated() {
                        ws.mark_fingerprint_adjudicated();
                    }
                }
                entry.workspace = Some(ws);
            }
            None => return false,
        }
        write_decision_locked(&mut map, &self.condvar, request_id, decision, challenge)
    }

    /// 锁外等待决策（G1：命令锁外；**只读不移除**——消费移除归 finalize）：
    /// 决策已写 → 返回之（条目留表等 finalize）；到期 → 返回
    /// [`ApprovalDecision::Timeout`]（默认拒绝；条目仍留表，期间迟到回传
    /// 按过期拒绝写）；条目不在册（已被消费的竞态）→ 保守 Denied。
    /// 到期时刻以登记值为准。
    pub(crate) fn await_decision(&self, request_id: uuid::Uuid) -> ApprovalDecision {
        let mut map = self.inner.lock().unwrap();
        loop {
            match map.get(&request_id) {
                Some(e) if e.decision.is_some() => {
                    // 只读返回：条目留给 finalize 单点消费
                    return e.decision.unwrap();
                }
                Some(e) if Instant::now() >= e.expires_at => {
                    // 到期默认拒绝；不移除（迟到回传按过期拒绝写）
                    return ApprovalDecision::Timeout;
                }
                Some(e) => {
                    let remaining = e.expires_at.saturating_duration_since(Instant::now());
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
                    // 条目已被消费（竞态）→ 保守视为拒绝
                    return ApprovalDecision::Denied;
                }
            }
        }
    }

    /// 三拍之三·收尾（finalize 阶段，重取命令锁后）：**唯一消费移除点**。
    /// 条目已被消费（极端竞态）→ `None`，调用方保守拒绝。按值返回：决策、
    /// 工作区与门负载随条目一并交出（调用方消费后即毁）。
    pub(crate) fn remove(&self, request_id: &uuid::Uuid) -> Option<ApprovalEntry> {
        self.inner.lock().unwrap().remove(request_id)
    }

    /// 待审条目是否带锁定态一体化标志（审批解锁辅助，表无关）：请求 id
    /// 不在册或条目为常规（解锁态）审批 → false。
    pub(crate) fn needs_unlock(&self, request_id: uuid::Uuid) -> bool {
        self.inner
            .lock()
            .unwrap()
            .get(&request_id)
            .map(|e| e.needs_unlock)
            .unwrap_or(false)
    }

    /// 当前待审批数（测试断言用）。
    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// 把所有待审批条目的到期时刻提前到当前时刻并唤醒等待者（测试专用）：
    /// 需要同时断言「回传落地」与「超时拒绝」的测试（如 #67 错误主密码
    /// 保留条目后 CLI 侧超时）不再依赖真实秒级等待——到期判定与默认拒绝
    /// 走既有 `await_decision` 语义，仅时钟被测试掌控。
    #[doc(hidden)]
    #[cfg(test)]
    pub(crate) fn expire_all_for_tests(&self) {
        let mut map = self.inner.lock().unwrap();
        let now = Instant::now();
        for e in map.values_mut() {
            e.expires_at = now;
        }
        self.condvar.notify_all();
    }
}

/// 决策写入（注册表锁内共用段，[`ApprovalRegistry::resolve`] /
/// [`ApprovalRegistry::store_workspace_and_resolve`]）：过期/未知 → 拒绝写；
/// 质询匹配 → 写决策 + 唤醒等待者。
fn write_decision_locked(
    map: &mut HashMap<uuid::Uuid, ApprovalEntry>,
    condvar: &Condvar,
    request_id: uuid::Uuid,
    decision: ApprovalDecision,
    challenge: &str,
) -> bool {
    let expired = map
        .get(&request_id)
        .map(|e| Instant::now() >= e.expires_at)
        .unwrap_or(true);
    if expired {
        // 拒绝写：迟到回传不得回翻等待侧已得的 Timeout；条目留待 finalize
        return false;
    }
    let matches = map
        .get(&request_id)
        .map(|e| e.challenge == challenge)
        .unwrap_or(false);
    if !matches {
        return false;
    }
    if let Some(e) = map.get_mut(&request_id) {
        e.decision = Some(decision);
    }
    condvar.notify_all();
    true
}

/// 审批请求草稿（issue #148 单点铸造的入参）：id / challenge / 超时不在
/// 其中——由 [`Daemon::open_gate_approval`] 唯一铸造；展示字段由各门自带。
/// 九字段克隆经 [`ApprovalDraft::new`] + `with_*` **单点构造**（issue #167：
/// 四个门事实可选字段在此唯一写 `None`，各门 begin 只补自己携带的事实）。
pub(crate) struct ApprovalDraft {
    pub starter: String,
    pub project_dir: String,
    pub command: String,
    /// 审批帧 keys（仅 key 名/条目名；弹窗展示用）。
    pub keys: Vec<String>,
    pub kind: lk_core::authz::ApprovalKind,
    /// #147：审批子类型事实（rule.add / rule.remove / item.put /
    /// item.delete 随帧回带 subKind；read/export/inject 恒 None）。
    pub sub_kind: Option<lk_core::authz::ApprovalSubKind>,
    /// #137：写审批的权威派生动作（随帧回带 writeAction）；非写审批 None。
    pub write_action: Option<lk_core::authz::WriteAction>,
    /// export 审批的数据包规模元信息；其余门 None。
    pub export_meta: Option<lk_core::authz::ExportMeta>,
    /// M2.98 指纹失配展示信息（identity-binding.md §7）；其余路径 None。
    pub fingerprint_mismatch: Option<lk_core::authz::FingerprintMismatch>,
}

impl ApprovalDraft {
    /// 单点构造（issue #167）：五个基字段 + 四个门事实可选字段缺省 `None`
    /// （此前各门手写九字段克隆、`None` 散布 7 处）。
    pub(crate) fn new(
        starter: String,
        project_dir: String,
        command: String,
        keys: Vec<String>,
        kind: lk_core::authz::ApprovalKind,
    ) -> Self {
        Self {
            starter,
            project_dir,
            command,
            keys,
            kind,
            sub_kind: None,
            write_action: None,
            export_meta: None,
            fingerprint_mismatch: None,
        }
    }

    /// 携带审批子类型事实（#147：规则门 / 写门随帧回带 subKind）。
    pub(crate) fn with_sub_kind(mut self, sub_kind: lk_core::authz::ApprovalSubKind) -> Self {
        self.sub_kind = Some(sub_kind);
        self
    }

    /// 携带写审批的权威派生动作（#137：随帧回带 writeAction）。
    pub(crate) fn with_write_action(mut self, action: lk_core::authz::WriteAction) -> Self {
        self.write_action = Some(action);
        self
    }

    /// 携带 export 审批的数据包规模元信息。
    pub(crate) fn with_export_meta(mut self, meta: lk_core::authz::ExportMeta) -> Self {
        self.export_meta = Some(meta);
        self
    }

    /// 携带指纹失配展示信息（M2.98 identity-binding.md §7）。
    pub(crate) fn with_fingerprint_mismatch(
        mut self,
        mismatch: lk_core::authz::FingerprintMismatch,
    ) -> Self {
        self.fingerprint_mismatch = Some(mismatch);
        self
    }
}

impl Daemon {
    /// 桌面审批界面在场判定（拍板 #28 候选 2 折入 daemon：原 core
    /// `LocalApprovalChannel::available` 的 `has_ui` 谓词）：只数**桌面来源**
    /// 推送订阅者——socket 订阅（任何持令牌进程可建立）不算「有界面」
    /// （#72/#78 方案 A）。`false` → 四门 begin 与锁态 precheck fail-closed
    /// 立即拒绝，不登记、不阻塞。
    pub(crate) fn approval_available(&self) -> bool {
        self.shared.push.desktop_subscriber_count() > 0
    }

    /// 门声明违例的 fail-closed 收线（issue #167，release 防御路径）：消费
    /// 误登记的待审批条目（迟到的 `approval.result` 按 unknown 拒绝写 →
    /// `accepted=false` + 失败提交审计；不残留无主弹窗空等超时）。按构造
    /// 不可达——needs_unlock 条目只能由声明支持一体化解锁的门登记。
    pub(crate) fn consume_gate_entry(&mut self, request_id: uuid::Uuid) {
        let _ = self.shared.approvals.remove(&request_id);
    }

    /// 审批请求单点铸造 + 注册表登记 + `authz.request` 广播（issue #148；
    /// 拍板 #28 候选 2 折入 daemon，取代 `ApprovalChannel::open`）：
    /// request_id / challenge / 超时在此**唯一铸造**（challenge 一次性等
    /// 不变量单点实现，#78），门负载条目随质询/到期一并入**审批注册表**
    /// （单表，不再有第二张 pending 表）；广播 `authz.request`（通知桥只投
    /// 桌面订阅者）。帧 `needsUnlock` 与条目 `needs_unlock` 同源（同一
    /// [`GateEntry`] 承载，不会漂移）。返回请求 id（等待方据此
    /// `await_decision`）。
    ///
    /// **E2E 规则自动批准分支**（补充拍板 #22 折入 daemon）：`rule_auto`
    /// 开启且 kind=Rule 时**不广播**（无 UI 参与）——登记后即刻写
    /// decision=Allowed（同一质询值；等待者即刻拿到决策）；inject/读/写
    /// 审批不在此分支，照旧要求 UI 在场。
    pub(crate) fn open_gate_approval(
        &mut self,
        draft: ApprovalDraft,
        pending: GateEntry,
    ) -> uuid::Uuid {
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let needs_unlock = pending.needs_unlock;
        self.shared
            .approvals
            .insert(request_id, pending, expires_at, challenge.clone());
        if self.rule_auto && draft.kind == lk_core::authz::ApprovalKind::Rule {
            // 登记 + 立即写 Allowed（同一质询值 resolve；等待者即刻拿到
            // 决策）；不广播 authz.request——自动批准无 UI 参与，弹窗不该
            // 出现（#22：仅规则审批，永不碰 inject/读值/写入）。
            let _ =
                self.shared
                    .approvals
                    .resolve(request_id, ApprovalDecision::Allowed, &challenge);
            return request_id;
        }
        // 广播 `authz.request`（通知 D 层弹窗；无密钥值；challenge 仅经本
        // 事件通道下发——守护进程侧通知桥只投给桌面订阅者，#78 方案 A；
        // kind/export_meta 供弹窗按审批类型渲染，M2.9 值披露；write_action
        // 供「记住」生成 actions=[当前动作] 最小写规则，#137）
        self.bus.emit(&VaultEvent::AuthzRequest {
            request_id,
            starter: draft.starter,
            project_dir: draft.project_dir,
            command: draft.command,
            keys: draft.keys,
            challenge,
            needs_unlock,
            kind: draft.kind,
            write_action: draft.write_action,
            export_meta: draft.export_meta,
            fingerprint_mismatch: draft.fingerprint_mismatch,
            sub_kind: draft.sub_kind,
        });
        request_id
    }

    /// 「本次执行所用 vault」统一取用原语（issue #150）：执行/审计入口收
    /// [`ActingVault`]——Shared = 共享 vault 读锁内取（`None` = 已锁定，
    /// K_audit 已擦除，语义由调用方决定：审计跳过 / 执行保守报错）；
    /// Temporary = 锁定态一体化的临时 vault 借用（审批工作区，见
    /// [`ApprovalWorkspace::vault`]）。执行与审计的 `_from` 变体对由此
    /// 全消（环境解析 / 读值执行 / 导出执行 / 审计同一入口）。
    pub(crate) fn with_acting_vault<R>(
        &self,
        acting: ActingVault<'_>,
        f: impl FnOnce(Option<&UnlockedVault>) -> R,
    ) -> R {
        match acting {
            ActingVault::Shared => {
                let guard = self.shared.vault.read().unwrap();
                f(guard.as_ref())
            }
            ActingVault::Temporary(v) => f(Some(v)),
        }
    }

    /// 四门合一的审计辅助（issue #148）：事件字段（starter/target/command/
    /// channel/result）由调用方提供，K_audit 按**本次执行所用 vault**
    /// （[`ActingVault`]）签名——调用方决定传共享 vault 还是临时 vault。
    /// 共享 vault 已锁定（K_audit 已擦除）→ 跳过审计（fail-closed 不留
    /// 审计内容，与既有口径一致）。
    pub(crate) fn audit_gate(
        &self,
        acting: ActingVault<'_>,
        starter: &str,
        target: &str,
        command: &str,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        let keys = match self.with_acting_vault(acting, |v| v.map(|v| v.keys().clone())) {
            // 共享 vault 已锁定 → K_audit 已擦除，跳过审计（既有口径）
            Some(keys) => keys,
            None => return,
        };
        let _ = self.audit.append(
            &keys,
            &EventInput {
                starter: starter.to_string(),
                target: target.to_string(),
                command: command.to_string(),
                result,
                channel,
                old_key_id: None,
                new_key_id: None,
            },
        );
    }
}

/// 本次执行所用 vault（acting vault；执行与审计的 K_audit 来源）。执行/
/// 审计入口统一收本枚举（issue #150：`with_acting_vault` 单点取用）——
/// 调用方决定传共享 vault 还是临时 vault；临时形态的 vault 由审批工作区
/// 持有（借用，生命周期不变量见 [`ApprovalWorkspace`]）。
pub(crate) enum ActingVault<'a> {
    /// 共享 vault（解锁态常态路径）；已锁定（`None`）→ 语义由调用方决定
    /// （审计跳过 / 执行保守报错）。
    Shared,
    /// 锁定态一体化的临时 vault（#67/#23；审批工作区借用）。
    Temporary(&'a UnlockedVault),
}

/// 门参数解析辅助（issue #148）：解析失败 → `invalid params` 响应行
/// （`Err`）。`id` 语义照旧由调用方决定（authz/disclosure 传请求 id，
/// rules/write 的解析错误现状为 null id——零行为变更）。
pub(crate) fn parse_gate_params<T: serde::de::DeserializeOwned>(
    id: &Value,
    params: Value,
) -> std::result::Result<T, String> {
    serde_json::from_value(params).map_err(|_| invalid_params(id.clone(), None))
}

/// `invalid params` 错误响应行（门参数校验失败路径共用；`detail` 为可选
/// 人读说明，进 error.data.detail）。
pub(crate) fn invalid_params(id: Value, detail: Option<String>) -> String {
    rpc_string(RpcResponse::err(
        id,
        ERR_INVALID_PARAMS,
        "invalid params",
        detail.map(|d| json!({ "detail": d })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::crypto::test_kdf_params;
    use lk_core::vault::init_vault_with_params;

    /// 登记用的远期到期时刻 + 质询值（测试默认值）。
    fn far_expiry() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    /// 构造一个 disclosure 门条目（字段全为简单值；GateKind 选哪个门不影响
    /// 条目级行为——这正是「表无关」的断言点）。
    fn disclosure_entry(needs_unlock: bool) -> GateEntry {
        let kind = GateKind::Disclosure(PendingDisclosure {
            method: lk_core::ipc::M_ITEM_GET.to_string(),
            item_id: uuid::Uuid::new_v4(),
            item_name: Some("item".to_string()),
            starter: "test".to_string(),
        });
        if needs_unlock {
            GateEntry::unified_unlock(kind)
        } else {
            GateEntry::approval(kind)
        }
    }

    /// 初始化临时 vault（审批工作区需要真实的 UnlockedVault 值；test KDF
    /// 参数下开销可忽略。UnlockedVault 不可 Clone，每次取用重新解锁）。
    fn init_vault(dir: &std::path::Path) {
        let mut audit = lk_core::audit::AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
    }

    /// 构造填充态审批工作区（临时解锁 vault 由测试主密码解锁）。
    fn workspace(dir: &std::path::Path) -> ApprovalWorkspace {
        ApprovalWorkspace::new(UnlockedVault::unlock(dir, "pw123456").unwrap())
    }

    #[test]
    fn unknown_request_is_not_needs_unlock() {
        let registry = ApprovalRegistry::new();
        assert!(!registry.needs_unlock(uuid::Uuid::new_v4()));
    }

    /// 表无关（issue #148 验收 1）：条目带 needs_unlock 即被审批解锁辅助
    /// 看见，不感知具体门；常规条目不误报。
    #[test]
    fn needs_unlock_is_seen_for_any_gate_entry() {
        let registry = ApprovalRegistry::new();
        let unified = uuid::Uuid::new_v4();
        let plain = uuid::Uuid::new_v4();
        registry.insert(unified, disclosure_entry(true), far_expiry(), "c".into());
        registry.insert(plain, disclosure_entry(false), far_expiry(), "c".into());
        assert!(registry.needs_unlock(unified));
        assert!(!registry.needs_unlock(plain));
    }

    /// 三拍生命周期（issue #166 / 拍板 #28 候选 2 验收）：登记 → 裁决写 →
    /// finalize 单点消费。覆盖质询不符不移除（#78）、await 只读不移除、
    /// 二次 remove 恒 None。
    #[test]
    fn approval_registry_three_beat_lifecycle() {
        let registry = ApprovalRegistry::new();
        let id = uuid::Uuid::new_v4();
        // 拍一·登记
        registry.insert(id, disclosure_entry(false), far_expiry(), "chal-1".into());
        assert_eq!(registry.pending_count(), 1);
        // 质询不符 → 拒绝写且**不移除**条目（#78 防伪回传打掉真审批）
        assert!(!registry.resolve(id, ApprovalDecision::Allowed, "wrong"));
        assert_eq!(registry.pending_count(), 1);
        // 拍二·裁决写：正确质询 → 决策入槽并唤醒等待者
        assert!(registry.resolve(id, ApprovalDecision::Allowed, "chal-1"));
        // await 只读：返回决策但条目仍在册（移除只归 finalize）
        assert_eq!(registry.await_decision(id), ApprovalDecision::Allowed);
        assert_eq!(
            registry.pending_count(),
            1,
            "await 只读不移除（finalize 唯一消费点）"
        );
        // 拍三·finalize 单点消费：决策随条目交出；再次 remove 恒 None
        let entry = registry.remove(&id).expect("条目在册");
        assert_eq!(entry.decision, Some(ApprovalDecision::Allowed));
        assert!(matches!(entry.kind, GateKind::Disclosure(_)));
        assert!(registry.remove(&id).is_none());
        assert_eq!(registry.pending_count(), 0);
    }

    /// 超时拍：await 已返 Timeout 后条目仍留表——finalize 未跑之间插入的
    /// 迟到回传**按过期拒绝写**（不得回翻等待结果），移除归 finalize。
    #[test]
    fn approval_registry_timeout_rejects_late_resolve_until_finalize() {
        let registry = ApprovalRegistry::new();
        let id = uuid::Uuid::new_v4();
        registry.insert(
            id,
            disclosure_entry(false),
            Instant::now() + Duration::from_millis(20),
            "c".into(),
        );
        // 等待侧超时默认拒绝（真实时钟驱动，20ms 窗口）
        assert_eq!(registry.await_decision(id), ApprovalDecision::Timeout);
        // 迟到回传（await 已返 Timeout、finalize 未跑）：拒绝写、条目不移除
        assert!(
            !registry.resolve(id, ApprovalDecision::Allowed, "c"),
            "迟到审批不得回翻已超时的等待结果"
        );
        assert_eq!(
            registry.pending_count(),
            1,
            "移除归 finalize（迟到回传无权移除）"
        );
        // finalize 仍能消费到条目（decision 槽未被迟到回传污染）
        let entry = registry.remove(&id).expect("finalize 消费");
        assert_eq!(entry.decision, None);
    }

    /// 一体化解锁路径的裁决写（issue #166）：条目不在册 → 放弃存储（工作区
    /// 随调用方 drop）；在册 + 正确质询 → 工作区入条目 + 决策写入 + 唤醒
    /// 等待者；finalize 消费时工作区随条目一并交出；消费后再存 → false
    /// （一次性语义）。
    #[test]
    fn approval_registry_unlock_path_workspace_and_decision() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let registry = ApprovalRegistry::new();
        // 条目已被 finalize 消费（超时竞态）→ false，工作区随调用方 drop
        let ghost = uuid::Uuid::new_v4();
        assert!(!registry.store_workspace_and_resolve(
            ghost,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "chal"
        ));
        // 在册 + 正确质询 → 工作区 + 决策一次落位
        let id = uuid::Uuid::new_v4();
        registry.insert(id, disclosure_entry(true), far_expiry(), "chal".into());
        assert!(registry.store_workspace_and_resolve(
            id,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "chal"
        ));
        assert_eq!(registry.await_decision(id), ApprovalDecision::Allowed);
        let entry = registry.remove(&id).expect("finalize 消费");
        assert!(entry.workspace.is_some(), "工作区随条目一并消费");
        assert!(entry.needs_unlock);
        // 消费后再存 → false（一次性语义）
        assert!(!registry.store_workspace_and_resolve(
            id,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "chal"
        ));
    }

    /// 审批工作区生命周期与条目严格一致（issue #150）：在册条目存储成功、
    /// 随 remove 返回（finalize 消费）；条目已被消费（超时竞态）→ false，
    /// 工作区随调用方作用域整体 drop。
    #[test]
    fn workspace_storage_follows_entry_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let registry = ApprovalRegistry::new();
        // 条目不在册 → 放弃存储（调用方作用域 drop）
        assert!(!registry.store_workspace_and_resolve(
            uuid::Uuid::new_v4(),
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "c"
        ));
        let id = uuid::Uuid::new_v4();
        registry.insert(id, disclosure_entry(true), far_expiry(), "c".into());
        assert!(registry.store_workspace_and_resolve(
            id,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "c"
        ));
        let entry = registry.remove(&id).expect("条目在册");
        assert!(entry.workspace.is_some());
        // 消费后再存 → false（一次性语义）
        assert!(!registry.store_workspace_and_resolve(
            id,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "c"
        ));
    }

    /// 单次裁决状态属于条目而非解锁材料（issue #150，#140 回归钉）：二次
    /// 审批条目已带「已裁决」工作区时，`approval.result` 重解锁存入**新的**
    /// 解锁材料——替换 vault 但不得重置已裁决标记，否则失配二次审批将再次
    /// 裁决、再次失配，形成裁决死循环。
    #[test]
    fn store_workspace_preserves_single_shot_state_of_repend_entry() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let registry = ApprovalRegistry::new();
        let id = uuid::Uuid::new_v4();
        // 模拟二次审批条目：工作区已裁决（finalize reopen 侧标记）
        registry.insert(id, disclosure_entry(true), far_expiry(), "c".into());
        let mut ws = workspace(dir.path());
        ws.mark_fingerprint_adjudicated();
        registry.store_workspace_and_resolve(id, ws, ApprovalDecision::Allowed, "c");
        // 回传重解锁：全新解锁材料替换既有工作区
        assert!(registry.store_workspace_and_resolve(
            id,
            workspace(dir.path()),
            ApprovalDecision::Allowed,
            "c"
        ));
        let entry = registry.remove(&id).expect("条目在册");
        let ws = entry.workspace.expect("工作区在册");
        assert!(
            ws.fingerprint_adjudicated(),
            "重解锁不得重置单次裁决状态（#140 裁决死循环由结构排除）"
        );
    }

    /// 工作区 = 临时解锁材料 + 单次裁决状态的一等对象（issue #150）：
    /// vault 只能借用（K_audit 在内存可用）；指纹裁决单发状态默认 false、
    /// 标记后 true（防裁决 → 审批 → 裁决死循环由结构承载，issue #140）。
    #[test]
    fn workspace_borrows_vault_and_carries_single_shot_state() {
        let dir = tempfile::tempdir().unwrap();
        init_vault(dir.path());
        let mut ws = workspace(dir.path());
        // 临时 vault 可借用：K_audit 在内存（审计可签名）
        let _ = ws.vault().keys();
        // 单次裁决状态：默认未裁决
        assert!(!ws.fingerprint_adjudicated());
        ws.mark_fingerprint_adjudicated();
        assert!(ws.fingerprint_adjudicated());
    }

    /// 条目构造器即声明（issue #150）：`GateEntry::approval` = 常规审批
    /// （needs_unlock=false，规则门/写门显式声明无需一体化解锁）；
    /// `GateEntry::unified_unlock` = 一体化解锁审批（needs_unlock=true，
    /// #67/#23）；工作区在两条路径上初始恒空。
    #[test]
    fn entry_constructors_declare_unlock_gate() {
        let plain = disclosure_entry(false);
        assert!(!plain.needs_unlock);
        assert!(plain.workspace.is_none());
        let unified = disclosure_entry(true);
        assert!(unified.needs_unlock);
        assert!(unified.workspace.is_none());
    }

    /// 参数解析辅助：成功路径原样解析；失败路径 = `invalid params` 行
    /// （id 原样回带——rules/write 传 null、authz/disclosure 传请求 id 的
    /// 既有语义由调用方决定）。
    #[test]
    fn parse_gate_params_ok_and_err() {
        #[derive(serde::Deserialize, Debug)]
        #[serde(rename_all = "camelCase")]
        struct P {
            id: uuid::Uuid,
        }
        let p: P = parse_gate_params(
            &json!(7),
            json!({ "id": "00000000-0000-0000-0000-000000000001" }),
        )
        .unwrap();
        assert_eq!(p.id, uuid::Uuid::from_u128(1));
        let line = parse_gate_params::<P>(&json!(7), json!({ "nope": 1 })).unwrap_err();
        let parsed: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["id"], json!(7));
        assert_eq!(parsed["error"]["code"], json!(ERR_INVALID_PARAMS));
        assert_eq!(parsed["error"]["message"], json!("invalid params"));
        assert_eq!(parsed["error"]["data"], Value::Null);
    }
}
