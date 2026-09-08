//! 执行计划路由（ADR-0001；术语见根目录 `CONTEXT.md`「执行计划路由」）。
//!
//! daemon 的**唯一分发点**：每个 RPC 方法映射到一种执行策略，方法的锁纪律
//! 由策略声明，不在各处理函数里手写。三种策略：
//!
//! - [`ExecutionStrategy::Inline`]：命令锁内跑完（vault.* / item.* / rule.*
//!   / audit.* / subscribe / approval.result 等）；
//! - [`ExecutionStrategy::OutsideLock`]：命令锁内预检 → **锁外**同步轮次 →
//!   锁内收尾活动时间戳（`sync.trigger`；两阶段同步——网络 I/O 不阻塞其他
//!   命令）；
//! - [`ExecutionStrategy::ApprovalDeferred`]：命令锁内预检 + begin → **锁外**
//!   等待审批决策（≤超时默认拒绝）→ 重取命令锁收尾（七个授权门方法；G1
//!   回归教训：等待不持有命令锁）。
//!
//! ApprovalDeferred 的锁编排收敛在**通用 deferred 编排器**
//! （[`run_deferred`]，issue #149）：每个审批延迟方法在流程注册表
//! （[`gate_flow`]）持有一份**静态门声明**（[`GateDecl`]，issue #167——
//! precheck/begin/finalize 三拍 + rependable/unlock_supported 两个事实
//! 布尔 + 拒绝响应渲染器），编排器只依赖「持命令锁跑一段」与「锁外等一次
//! 决策」两个原语（[`DeferredSeam`]）并按声明执行——fail-closed 次序与
//! 分层裁决结果的字节收线只此一处承载；RePended 循环内建（锁定态一体化
//! 指纹失配转二次审批，issue #140），注入裁决不再是编排特例。
//!
//! 两条缝共用同一套编排（interface 即测试面，等价由构造保证）：
//!
//! - [`route`]（主缝）：生产（CLI socket / 桌面内嵌）与并发回归测试的唯一
//!   入口；按策略编排加锁/解锁窗口；
//! - [`Daemon::handle`](crate::Daemon::handle)（直调）：签名不变，查同一张
//!   策略表与流程注册表，以**持锁形态**（[`DirectSeam`]：locked 即透传，
//!   无解锁窗口可释放——单线程直调下锁窗口本就不可观察）驱动**同一个**
//!   编排器，请求/响应与主缝一致不再是测试维持而是构造使然。
//!
//! Inline / OutsideLock 不进编排器——ADR-0001 否决的是跨策略泛化，收敛
//! 只在 ApprovalDeferred 流之间进行（语义完全同构）。
//!
//! 新增 RPC 方法 = 在 [`strategy_of`] 登记（新方法默认 Inline，两阶段的
//! 显式声明策略）；新增审批门方法 = [`strategy_of`] 一行 + [`gate_flow`]
//! 一行 + 门模块一份静态门声明（含渲染器），不抄锁样板。

use std::sync::{Arc, Mutex};

use lk_core::authz::ApprovalDecision;
use lk_core::ipc::*;
use serde_json::Value;

use crate::daemon::gate_kit::{DeferredOutcome, GateBegin, GateDeny};
use crate::transport::PeerInfo;
use crate::{extract_token, rpc_string, Daemon, SharedDaemon};

/// RPC 方法的执行策略（锁纪律声明；见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStrategy {
    /// 命令锁内跑完。
    Inline,
    /// 锁内预检 → 锁外工作 → 锁内收尾（`sync.trigger`）。
    OutsideLock,
    /// 锁内预检 + begin → 锁外等待审批 → 锁内收尾（七个授权门方法）。
    ApprovalDeferred,
}

/// 方法 → 策略映射（唯一分发依据；新增方法在此登记，缺省 Inline）。
///
/// M2.9 值披露（value-disclosure.md §5.1）：`item.get` / `item.export`
/// 升为 [`ExecutionStrategy::ApprovalDeferred`]——值离开守护进程必须是
/// 授权事件（读规则命中静默放行，否则弹窗/拒绝）。
///
/// 规则管理审批门（补充拍板 #22）：`rule.add` / `rule.remove` 同升
/// ApprovalDeferred——授权的建立与撤销都是授权事件（desktop 直调豁免、
/// headless fail-closed，见 daemon/rules.rs）；`rule.list` 维持 Inline
/// （只读元数据）。
///
/// 写入授权门（补充拍板 #24，write-gate.md §5.1）：`item.put` /
/// `item.delete` 升为 ApprovalDeferred——**写 = 授权事件**（写规则命中
/// 静默放行 / 桌面弹窗批准 / 否则拒绝；delete 恒弹窗）；`item.list`
/// 维持 Inline。
pub fn strategy_of(method: &str) -> ExecutionStrategy {
    match method {
        M_SYNC_TRIGGER => ExecutionStrategy::OutsideLock,
        M_AUTHZ_EVALUATE | M_ITEM_GET | M_ITEM_EXPORT | M_ITEM_PUT | M_ITEM_DELETE | M_RULE_ADD
        | M_RULE_REMOVE => ExecutionStrategy::ApprovalDeferred,
        _ => ExecutionStrategy::Inline,
    }
}

// -------------------------------------------------------------------------
// 审批门流程注册表（issue #149：通用 deferred 编排器的声明面；
// issue #167：trait 空壳 → 静态门声明）
// -------------------------------------------------------------------------

/// 门声明（issue #167 / 拍板 #28 候选 3；术语见 CONTEXT.md「门声明」）：
/// 每个裁决门的一份**静态声明**——precheck / begin / finalize 三个 fn 指针、
/// 「可否二次审批」「可否锁态一体化解锁」两个事实布尔、门名与拒绝响应渲染器。
/// [`gate_flow`] 返回它；通用裁决骨架 [`run_deferred`] 按声明执行：
/// fail-closed 次序（预检先于裁决 / 拒绝检查先于登记 / 分层结果字节收线
/// 唯一 / 声明契约违例 fail-closed）**只此一处**承载。
///
/// 布尔是一等数据：release 下被编排器**真消费**（不可 RePended 的门返回
/// RePended / 不支持一体化解锁的门登记 needs_unlock 条目 → 立即按本门
/// 拒绝尾 fail-closed，§0「行为保持」唯一例外脚注——按构造不可达的防御
/// 路径硬化；debug 仍断言）。取代 `DeferredFlow` trait + 四个 `*Flow`
/// 纯委托空壳形态（issue #149 的过渡结构）。
pub(crate) struct GateDecl {
    /// 门名（诊断 / 契约违例消息）。
    pub(crate) name: &'static str,
    /// 可否 RePended（二次审批）：仅注入门 true（锁态一体化补指纹裁决
    /// 失配转二次审批，issue #140）；声明 false 的门 finalize 恒不返回
    /// [`DeferredOutcome::RePended`]。
    pub(crate) rependable: bool,
    /// 是否支持锁态一体化解锁（#67 inject / #23 读通道，issue #150 显式
    /// 声明）：规则门 / 写门恒 false——产品决策留档（规则门锁态
    /// `session.invalid` 先行；写门无解锁窗，write-gate.md §5.3 拍板
    /// 保留）；needs_unlock 条目只能由声明 true 的门登记。
    pub(crate) unlock_supported: bool,
    /// 阶段①预检（命令锁内）：会话/锁态分流（锁态一体化放行 or
    /// fail-closed）。失败 → `session.invalid`（会话前置失败，执行层），
    /// 不进 begin。
    pub(crate) precheck: fn(&Daemon, Option<&[u8]>) -> bool,
    /// 阶段①（命令锁内）：六步裁决（解析 → desktop 豁免 → starter/cwd →
    /// fail-closed → 规则命中 → 登记广播），返回**分层裁决结果**
    /// （拒绝 reason / 放行·直返负载 / 未命中需审批）。
    pub(crate) begin: fn(
        daemon: &mut Daemon,
        method: &str,
        id: Value,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin,
    /// 阶段③（重取命令锁）：收决策收尾，返回**分层结果**（决策结局 vs
    /// 执行结果两层）。
    pub(crate) finalize: fn(
        daemon: &mut Daemon,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> DeferredOutcome,
    /// 拒绝响应渲染器：(门 × 锁态/会话态 × reason) → 响应字节（**唯一
    /// 决定点**，issue #167）。必须拿 daemon 上下文而非「决策 → 字节」纯
    /// 函数——同一 reason（no_ui / unknown_starter）跨门跨锁态字节不同
    /// （解锁态 inject=`ok{no_ui}` vs disclosure=`authz.denied`(-32017)；
    /// 锁态 headless inject=`session.invalid` 是会话前置失败，不经渲染器
    /// ——分层见 [`GateBegin`] 类型文档），否则 6 类 spec 钉死的
    /// fail-closed 码会被压平（§1.6；golden 表测试钉住）。
    pub(crate) render_deny: fn(daemon: &Daemon, id: Value, deny: GateDeny) -> String,
}

/// 流程注册表（唯一分发依据）：method → 门声明。与 [`strategy_of`] 的
/// ApprovalDeferred 集合严格同步（完整性测试钉住，见本模块 tests）；
/// 新增审批门方法 = [`strategy_of`] 一行 + 此处一行 + 门模块一份静态声明。
pub(crate) fn gate_flow(method: &str) -> Option<&'static GateDecl> {
    match method {
        M_AUTHZ_EVALUATE => Some(&crate::daemon::authz::AUTHZ_GATE),
        M_ITEM_GET | M_ITEM_EXPORT => Some(&crate::daemon::disclosure::DISCLOSURE_GATE),
        M_RULE_ADD | M_RULE_REMOVE => Some(&crate::daemon::rules::RULE_GATE),
        M_ITEM_PUT | M_ITEM_DELETE => Some(&crate::daemon::write::WRITE_GATE),
        _ => None,
    }
}

/// 缝抽象（issue #149）：编排器只依赖「持命令锁执行一段」与「锁外等一次
/// 决策」两个原语。route 缝（[`RouteSeam`]，主缝：真正加锁/解锁）与直调
/// 缝（[`DirectSeam`]，调用方已持锁：locked 即透传）实现同一抽象——
/// route 与直调的等价由构造保证，不再靠等价性测试维持。
pub(crate) trait DeferredSeam {
    /// 持命令锁执行一段（route 缝 = 加锁 → 执行 → 解锁；直调缝 = 透传）。
    fn locked<R>(&mut self, f: impl FnOnce(&mut Daemon) -> R) -> R;

    /// 锁外等待一次决策（≤超时默认拒绝）。
    fn await_decision(&self, request_id: uuid::Uuid) -> ApprovalDecision;
}

/// 主缝（`route`）：每次进入编排段都（重）取命令锁——锁外等待期间其他
/// 命令照常服务（G1）。
struct RouteSeam<'a> {
    state: &'a Arc<Mutex<Daemon>>,
    shared: &'a Arc<SharedDaemon>,
}

impl DeferredSeam for RouteSeam<'_> {
    fn locked<R>(&mut self, f: impl FnOnce(&mut Daemon) -> R) -> R {
        let mut guard = self.state.lock().expect("daemon mutex poisoned");
        f(&mut guard)
    }

    fn await_decision(&self, request_id: uuid::Uuid) -> ApprovalDecision {
        self.shared.approvals.await_decision(request_id)
    }
}

/// 直调缝（`Daemon::handle`）：调用方已持命令锁，locked 即透传（无解锁
/// 窗口可释放——单线程直调下锁窗口本就不可观察）；等待与主缝同源
/// （同一审批注册表）。
pub(crate) struct DirectSeam<'a> {
    daemon: &'a mut Daemon,
}

impl<'a> DirectSeam<'a> {
    pub(crate) fn new(daemon: &'a mut Daemon) -> Self {
        Self { daemon }
    }
}

impl DeferredSeam for DirectSeam<'_> {
    fn locked<R>(&mut self, f: impl FnOnce(&mut Daemon) -> R) -> R {
        f(&mut *self.daemon)
    }

    fn await_decision(&self, request_id: uuid::Uuid) -> ApprovalDecision {
        self.daemon.shared().approvals.await_decision(request_id)
    }
}

/// 通用 deferred 编排器（issue #149；issue #167 起按静态门声明执行）：
/// 全部七个审批延迟方法共用同一裁决骨架——①命令锁内空闲超时检查 + 预检 +
/// begin（需要审批则登记待审批 + 广播 `authz.request`）→ ②命令锁外等待
/// 决策（≤超时默认拒绝；等待期间其他命令照常服务，G1）→ ③重取命令锁
/// 收尾；finalize 返回 RePended 即回到②（内建循环；仅 `rependable` 门
/// 声明可能产生，issue #140）。
///
/// fail-closed 次序只此一处承载（issue #167）：
/// - 预检失败 → `session.invalid`（会话前置失败，先于任何裁决，不进 begin）；
/// - begin 裁决拒绝 → 门声明渲染器在**同一锁段**内渲染字节（锁态/会话态
///   与裁决时刻一致——渲染唯一决定点，六类 spec 钉死的 fail-closed 码不
///   跨门压平）；
/// - 一体化解锁声明一致性：needs_unlock 条目只能由声明支持的门登记，
///   违例 release fail-closed（布尔一等数据）；
/// - finalize 分层结果的字节收线唯一在 [`settle_outcome`]（决策结局与执行
///   层保守拒绝走渲染器；`session.invalid` = 执行失败，跨门统一）；
/// - RePended 契约：声明不可 RePended 却返回 → release 立即 fail-closed
///   （§0「行为保持」唯一例外脚注）。
///
/// 活动时间戳在收尾终局刷新（RePended 不刷），与常规路径语义一致。
pub(crate) fn run_deferred<S: DeferredSeam>(
    seam: &mut S,
    gate: &GateDecl,
    method: &str,
    id: Value,
    token: Option<Vec<u8>>,
    params: Value,
    peer: &PeerInfo,
) -> String {
    // ① 命令锁内：预检 + begin（裁决拒绝同锁段渲染）
    let begin = seam.locked(|g| {
        g.auto_lock_if_idle();
        if !(gate.precheck)(g, token.as_deref()) {
            return None;
        }
        let begin = (gate.begin)(g, method, id.clone(), params, peer);
        Some(match begin {
            GateBegin::Deny(deny) => GateBegin::Final((gate.render_deny)(g, id.clone(), deny)),
            GateBegin::Pending { request_id } => {
                // 一体化解锁声明一致性（布尔一等数据，release 真消费）：
                // needs_unlock 条目只能由声明支持一体化解锁的门登记——
                // 违例即 fail-closed（消费误登记条目 + 本门拒绝尾，不进入
                // 等待；按构造不可达的防御硬化，§0 例外脚注）。debug 仍断言。
                let violated = g.pending_needs_unlock(request_id) && !gate.unlock_supported;
                debug_assert!(
                    !violated,
                    "{} 声明不支持一体化解锁却登记 needs_unlock 条目",
                    gate.name
                );
                if violated {
                    unlock_violation_fail_closed(g, gate, id.clone(), request_id)
                } else {
                    GateBegin::Pending { request_id }
                }
            }
            passthrough => passthrough,
        })
    });
    let Some(begin) = begin else {
        return rpc_string(session_invalid(id));
    };
    match begin {
        GateBegin::Final(resp) => resp,
        // begin 拒绝已在①锁段内经门声明渲染器折为 Final（字节唯一决定点）；
        // 此臂按构造不可达。
        GateBegin::Deny(_) => unreachable!("begin 拒绝已在锁段①内渲染为 Final"),
        GateBegin::Pending { request_id } => {
            let mut request_id = request_id;
            loop {
                // ② 锁外等待（不持命令锁；vault/审批注册表短锁除外，G1）
                let decision = seam.await_decision(request_id);
                // ③ 重取命令锁收尾（分层结果 → 字节单点收线）
                let step = seam.locked(|g| {
                    let raw = (gate.finalize)(g, id.clone(), request_id, decision);
                    // RePended 契约（debug 断言半边；release 语义在
                    // settle_outcome 的违例折叠）。
                    if matches!(raw, DeferredOutcome::RePended { .. }) && !gate.rependable {
                        debug_assert!(
                            gate.rependable,
                            "{} 声明不可 RePended 却返回 RePended（release 已 fail-closed）",
                            gate.name
                        );
                    }
                    settle_outcome(g, gate, id.clone(), raw)
                });
                match step {
                    Ok(resp) => break resp,
                    Err(next) => request_id = next,
                }
            }
        }
    }
}

/// finalize 分层结果的字节收线（issue #167 **唯一渲染点**；编排器与直驱
/// finalize 的测试共用）：决策结局 [`DeferredOutcome::Denied`] 与执行层保守
/// 拒绝 [`DeferredOutcome::ExecutionDenied`] 都走门声明渲染器（同一 reason
/// 跨门字节不同，不压平）；执行失败 [`DeferredOutcome::SessionInvalid`] 跨门
/// 统一 `session.invalid`；终局刷新活动时间戳（与常规路径语义一致）。
///
/// RePended 契约违例的 **release 语义**（§0「行为保持」唯一例外脚注）：
/// 声明不可 RePended 的门返回 RePended → 立即 fail-closed——不等待无主的
/// 二次审批，按本门拒绝尾收线（按构造不可达的防御路径硬化，裁决结果不变）。
/// debug 断言半边在 [`run_deferred`]（本函数保持纯 release 语义，供测试
/// 直驱钉字节）。返回 `Err(next_request_id)` 表示正常转二次审批（回到
/// 锁外等待）。
pub(crate) fn settle_outcome(
    g: &mut Daemon,
    gate: &GateDecl,
    id: Value,
    raw: DeferredOutcome,
) -> std::result::Result<String, uuid::Uuid> {
    // RePended 契约违例（不可达防御路径）：折为本门拒绝尾
    let raw = if matches!(raw, DeferredOutcome::RePended { .. }) && !gate.rependable {
        DeferredOutcome::Denied(GateDeny::Rejected)
    } else {
        raw
    };
    match raw {
        DeferredOutcome::RePended { request_id: next } => Err(next),
        DeferredOutcome::Executed(resp) => {
            g.touch_activity();
            Ok(resp)
        }
        DeferredOutcome::SessionInvalid => {
            g.touch_activity();
            Ok(rpc_string(session_invalid(id)))
        }
        DeferredOutcome::ExecutionDenied(deny) | DeferredOutcome::Denied(deny) => {
            g.touch_activity();
            Ok((gate.render_deny)(g, id, deny))
        }
    }
}

/// 一体化解锁声明违例的 release fail-closed 收线（§0 例外脚注的 release
/// 半边；debug 断言在 [`run_deferred`]，本函数保持纯 release 语义供测试
/// 直驱）：消费误登记的待审批条目（迟到的 `approval.result` 按 unknown
/// 拒绝写 → `accepted=false` + 失败提交审计，不残留无主弹窗空等超时）+
/// 本门拒绝尾，不进入等待。
fn unlock_violation_fail_closed(
    g: &mut Daemon,
    gate: &GateDecl,
    id: Value,
    request_id: uuid::Uuid,
) -> GateBegin {
    g.consume_gate_entry(request_id);
    GateBegin::Final((gate.render_deny)(g, id, GateDeny::Rejected))
}

/// 主缝：按策略编排命令锁，处理一行 JSON-RPC 请求，返回一行响应。
///
/// 生产传输层与测试统一经此入口；请求行无法解析时按 Inline 兜底（由
/// `handle` 产出 parse-error 响应，行为与既有协议一致）。
pub fn route(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    line: &str,
    peer: &PeerInfo,
) -> String {
    let strategy = serde_json::from_str::<RpcRequest>(line)
        .ok()
        .map(|req| strategy_of(&req.method));
    match strategy {
        Some(ExecutionStrategy::OutsideLock) => sync_trigger_outside_lock(state, shared, line),
        Some(ExecutionStrategy::ApprovalDeferred) => {
            let req: RpcRequest = serde_json::from_str(line).expect("route 已按策略分派");
            // 策略表与流程注册表同步由完整性测试钉住；生产不可达 None。
            let gate = gate_flow(&req.method).expect("策略表与流程注册表同步");
            let token = extract_token(&req.params);
            let mut seam = RouteSeam { state, shared };
            run_deferred(
                &mut seam,
                gate,
                &req.method,
                req.id.clone(),
                token,
                req.params,
                peer,
            )
        }
        _ => {
            let mut guard = state.lock().expect("daemon mutex poisoned");
            guard.handle(line, peer)
        }
    }
}

/// OutsideLock 编排（`sync.trigger`）：①命令锁内会话预检（含空闲超时检查）
/// → ②轮次主体在命令锁外执行（网络 I/O 期间其他命令照常服务；与后台轮询
/// 并发安全——数据层 CAS + vault 短写锁兜底）→ ③活动时间戳收尾（命令锁内；
/// 与常规路径 `last_activity` 语义一致）。
fn sync_trigger_outside_lock(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    line: &str,
) -> String {
    let req: RpcRequest = serde_json::from_str(line).expect("route 已按策略分派");
    let id = req.id;
    let token = extract_token(&req.params);
    // ① 会话预检（短暂持命令锁）
    let session_ok = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        guard.trigger_precheck(token.as_deref())
    };
    if !session_ok {
        return serde_json::to_string(&session_invalid(id)).unwrap_or_else(|_| "{}".into());
    }
    // ② 轮次：命令锁外执行
    let resp = match crate::run_sync_round(shared) {
        Ok(summary) => RpcResponse::ok(id, serde_json::to_value(summary).unwrap_or(Value::Null)),
        Err(e) => crate::sync_fail_response(id, &e),
    };
    // ③ 活动时间戳（命令锁内）
    if let Ok(mut guard) = state.lock() {
        guard.touch_activity();
    }
    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::VecDeque;

    // ---------------------------------------------------------------------
    // 编排器单测（issue #149 / #167）：mock 门声明 + MockSeam 驱动
    // run_deferred，钉三阶段骨架、内建 RePended 循环、begin 拒绝渲染与
    // 两条声明契约违例的 release fail-closed 路径；真实门由各门集成测试
    // 与响应字节 golden 表（tests/gate_golden.rs）覆盖。
    // ---------------------------------------------------------------------

    /// mock 门状态：fn 指针无捕获 → 只能进程级；四个编排器测试经
    /// [`MOCK_LOCK`] 串行防交叉污染（取锁后先覆写全量状态，用毕即弃）。
    struct MockGateState {
        precheck_ok: bool,
        /// begin 脚本（一次性取出；重复调用即脚本耗尽）。
        begin: Option<GateBegin>,
        /// begin 返回 Pending 时是否向真实审批注册表登记 needs_unlock 条目
        /// （驱动 unlock_supported 违例路径）。
        register_needs_unlock: bool,
        /// finalize 脚本：逐次弹出（耗尽后恒 Executed("{}")）。
        finalize_script: VecDeque<DeferredOutcome>,
        precheck_calls: usize,
        begin_calls: usize,
        finalize_calls: usize,
    }

    impl MockGateState {
        const EMPTY: MockGateState = MockGateState {
            precheck_ok: true,
            begin: None,
            register_needs_unlock: false,
            finalize_script: VecDeque::new(),
            precheck_calls: 0,
            begin_calls: 0,
            finalize_calls: 0,
        };
    }

    static MOCK: Mutex<MockGateState> = Mutex::new(MockGateState::EMPTY);

    /// 编排器 mock 测试串行锁（fn 指针无捕获 → 状态进程级，并行会互染）。
    static MOCK_LOCK: Mutex<()> = Mutex::new(());

    fn mock_precheck(_daemon: &Daemon, _token: Option<&[u8]>) -> bool {
        let mut m = MOCK.lock().unwrap();
        m.precheck_calls += 1;
        m.precheck_ok
    }

    fn mock_begin(
        daemon: &mut Daemon,
        _method: &str,
        _id: Value,
        _params: Value,
        _peer: &PeerInfo,
    ) -> GateBegin {
        let mut m = MOCK.lock().unwrap();
        m.begin_calls += 1;
        let begin = m.begin.take().expect("begin 脚本缺失");
        if m.register_needs_unlock {
            // 向真实审批注册表登记 needs_unlock 条目（驱动违例路径）
            let GateBegin::Pending { request_id } = begin else {
                panic!("register_needs_unlock 只配 Pending begin")
            };
            let kind = crate::daemon::gate_kit::GateKind::Disclosure(
                crate::daemon::disclosure::PendingDisclosure {
                    method: M_ITEM_GET.to_string(),
                    item_id: uuid::Uuid::new_v4(),
                    item_name: Some("item".to_string()),
                    starter: "test".to_string(),
                },
            );
            daemon.shared().approvals.insert(
                request_id,
                crate::daemon::gate_kit::GateEntry::unified_unlock(kind),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                "mock-challenge".into(),
            );
            return GateBegin::Pending { request_id };
        }
        begin
    }

    fn mock_finalize(
        _daemon: &mut Daemon,
        _id: Value,
        _request_id: uuid::Uuid,
        _decision: ApprovalDecision,
    ) -> DeferredOutcome {
        let mut m = MOCK.lock().unwrap();
        m.finalize_calls += 1;
        m.finalize_script
            .pop_front()
            .unwrap_or(DeferredOutcome::Executed("{}".into()))
    }

    /// mock 渲染器：字节含 reason（钉「渲染经门声明而非全局决策→字节」）。
    fn mock_render_deny(_daemon: &Daemon, _id: Value, deny: GateDeny) -> String {
        format!(r#"{{"mockDeny":"{}"}}"#, deny.as_str())
    }

    /// 常规 mock 门（两布尔均 true）。
    static MOCK_GATE: GateDecl = GateDecl {
        name: "mock",
        rependable: true,
        unlock_supported: true,
        precheck: mock_precheck,
        begin: mock_begin,
        finalize: mock_finalize,
        render_deny: mock_render_deny,
    };

    /// 不可 RePended 的 mock 门（驱动 RePended 契约违例 fail-closed 路径）。
    static MOCK_NONREPEND_GATE: GateDecl = GateDecl {
        name: "mock-nonrepend",
        rependable: false,
        unlock_supported: true,
        precheck: mock_precheck,
        begin: mock_begin,
        finalize: mock_finalize,
        render_deny: mock_render_deny,
    };

    /// 不支持一体化解锁的 mock 门（驱动 needs_unlock 声明违例 fail-closed
    /// 路径）。
    static MOCK_NO_UNLOCK_GATE: GateDecl = GateDecl {
        name: "mock-no-unlock",
        rependable: true,
        unlock_supported: false,
        precheck: mock_precheck,
        begin: mock_begin,
        finalize: mock_finalize,
        render_deny: mock_render_deny,
    };

    /// 装配 mock 状态（须持 [`MOCK_LOCK`] 串行）。
    fn install_mock(state: MockGateState) {
        *MOCK.lock().unwrap() = state;
    }

    /// 读取调用计数（begin / finalize / precheck）。
    fn mock_calls() -> (usize, usize, usize) {
        let m = MOCK.lock().unwrap();
        (m.begin_calls, m.finalize_calls, m.precheck_calls)
    }

    /// Mock 缝：锁段计数 + 等待计数 + 预编程决策队列（耗尽后恒 Denied）；
    /// 持有一个真实 Daemon（tempdir 与实例同生命周期）供编排器触达
    /// auto_lock_if_idle / touch_activity / 审批注册表。
    struct MockSeam {
        _dir: tempfile::TempDir,
        daemon: Daemon,
        decisions: Mutex<VecDeque<ApprovalDecision>>,
        lock_segments: std::sync::atomic::AtomicUsize,
        awaits: std::sync::atomic::AtomicUsize,
    }

    impl MockSeam {
        fn new(decisions: VecDeque<ApprovalDecision>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let daemon = Daemon::start(dir.path()).unwrap();
            Self {
                _dir: dir,
                daemon,
                decisions: Mutex::new(decisions),
                lock_segments: std::sync::atomic::AtomicUsize::new(0),
                awaits: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn lock_segments(&self) -> usize {
            self.lock_segments.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn awaits(&self) -> usize {
            self.awaits.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DeferredSeam for MockSeam {
        fn locked<R>(&mut self, f: impl FnOnce(&mut Daemon) -> R) -> R {
            self.lock_segments
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            f(&mut self.daemon)
        }

        fn await_decision(&self, _request_id: uuid::Uuid) -> ApprovalDecision {
            self.awaits
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.decisions
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(ApprovalDecision::Denied)
        }
    }

    fn mock_peer() -> PeerInfo {
        PeerInfo::unknown()
    }

    /// 预检失败 → session.invalid：begin / finalize 均不执行。
    #[test]
    fn orchestrator_fails_closed_on_precheck() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            precheck_ok: false,
            begin: Some(GateBegin::Final("begin".into())),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = run_deferred(
            &mut seam,
            &MOCK_GATE,
            M_AUTHZ_EVALUATE,
            json!(7),
            None,
            json!({}),
            &mock_peer(),
        );
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], json!(ERR_SESSION_INVALID));
        let (begin_calls, finalize_calls, precheck_calls) = mock_calls();
        assert_eq!(begin_calls, 0);
        assert_eq!(finalize_calls, 0);
        assert_eq!(precheck_calls, 1);
    }

    /// begin 直返 Final（放行负载/协议直返）→ 响应透传，finalize 不执行。
    #[test]
    fn orchestrator_passthrough_final() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            begin: Some(GateBegin::Final(r#"{"ok":true}"#.into())),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = run_deferred(
            &mut seam,
            &MOCK_GATE,
            M_ITEM_GET,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"ok":true}"#);
        let (_, finalize_calls, _) = mock_calls();
        assert_eq!(finalize_calls, 0);
    }

    /// begin 裁决拒绝 → 门声明渲染器渲染字节（同一锁段内，不进等待，
    /// finalize 不执行）——渲染唯一决定点，字节不在门 begin 手写。
    #[test]
    fn orchestrator_renders_begin_deny_via_gate_renderer() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            begin: Some(GateBegin::Deny(GateDeny::NoUi)),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = run_deferred(
            &mut seam,
            &MOCK_GATE,
            M_ITEM_GET,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"mockDeny":"no_ui"}"#);
        let (begin_calls, finalize_calls, _) = mock_calls();
        assert_eq!(begin_calls, 1);
        assert_eq!(finalize_calls, 0);
        assert_eq!(seam.awaits(), 0, "begin 拒绝不进审批等待");
        assert_eq!(seam.lock_segments(), 1, "渲染收敛在 begin 同一锁段");
    }

    /// Pending → 锁外等一次决策 → 锁内收尾 Executed：三阶段各一段锁。
    #[test]
    fn orchestrator_pending_done_roundtrip() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            begin: Some(GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            }),
            finalize_script: VecDeque::from([DeferredOutcome::Executed(
                r#"{"allowed":true}"#.into(),
            )]),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::from([ApprovalDecision::Allowed]));
        let resp = run_deferred(
            &mut seam,
            &MOCK_GATE,
            M_ITEM_EXPORT,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"allowed":true}"#);
        // 段①（预检+begin）+ 段③（finalize）= 两段锁；等待在锁外。
        assert_eq!(seam.lock_segments(), 2);
        let (_, finalize_calls, _) = mock_calls();
        assert_eq!(finalize_calls, 1);
    }

    /// RePended 循环内建（issue #149 / #140）：finalize 转二次审批 → 回到
    /// 锁外等待 → 二次决策落地后收尾；循环次数由 finalize 脚本承载。
    #[test]
    fn orchestrator_builtin_repend_loop() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let next = uuid::Uuid::new_v4();
        install_mock(MockGateState {
            begin: Some(GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            }),
            finalize_script: VecDeque::from([
                DeferredOutcome::RePended { request_id: next },
                DeferredOutcome::Executed(r#"{"allowed":false}"#.into()),
            ]),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::from([
            ApprovalDecision::Allowed, // 首次决策 → finalize 转 RePended
            ApprovalDecision::Allowed, // 二次决策 → finalize Executed
        ]));
        let resp = run_deferred(
            &mut seam,
            &MOCK_GATE,
            M_AUTHZ_EVALUATE,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"allowed":false}"#);
        let (_, finalize_calls, _) = mock_calls();
        assert_eq!(finalize_calls, 2);
        assert_eq!(seam.lock_segments(), 3);
        assert_eq!(seam.awaits(), 2);
    }

    /// RePended 契约违例的 **release 语义**（issue #167 / §0 唯一「行为
    /// 保持」例外脚注；debug 断言半边由 should_panic 测试钉住）：声明不可
    /// RePended 的门 finalize 返回 RePended → settle_outcome 折为本门拒绝
    /// 尾——不等待无主的二次审批。
    #[test]
    fn settle_outcome_fails_closed_on_repend_violation() {
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = settle_outcome(
            &mut seam.daemon,
            &MOCK_NONREPEND_GATE,
            json!(1),
            DeferredOutcome::RePended {
                request_id: uuid::Uuid::new_v4(),
            },
        )
        .expect("违例不得转二次审批");
        assert_eq!(
            resp, r#"{"mockDeny":"rejected"}"#,
            "违例按本门拒绝尾收线（渲染器字节）"
        );
        // 正常路径回归：可 RePended 声明的 RePended 原样转出
        let next = uuid::Uuid::new_v4();
        let out = settle_outcome(
            &mut seam.daemon,
            &MOCK_GATE,
            json!(1),
            DeferredOutcome::RePended { request_id: next },
        )
        .expect_err("可 RePended 声明正常转二次审批");
        assert_eq!(out, next);
    }

    /// 一体化解锁声明违例的 **release 语义**（issue #167，布尔一等数据；
    /// debug 断言半边由 should_panic 测试钉住）：误登记的 needs_unlock 条目
    /// 被消费（迟到的 approval.result 按 unknown 拒绝写）+ 本门拒绝尾。
    #[test]
    fn unlock_violation_fail_closed_consumes_entry() {
        let mut seam = MockSeam::new(VecDeque::new());
        // 向真实审批注册表登记 needs_unlock 条目（模拟误登记）
        let request_id = uuid::Uuid::new_v4();
        {
            let kind = crate::daemon::gate_kit::GateKind::Disclosure(
                crate::daemon::disclosure::PendingDisclosure {
                    method: M_ITEM_GET.to_string(),
                    item_id: uuid::Uuid::new_v4(),
                    item_name: Some("item".to_string()),
                    starter: "test".to_string(),
                },
            );
            seam.daemon.shared().approvals.insert(
                request_id,
                crate::daemon::gate_kit::GateEntry::unified_unlock(kind),
                std::time::Instant::now() + std::time::Duration::from_secs(30),
                "mock-challenge".into(),
            );
        }
        assert_eq!(seam.daemon.shared().approvals.pending_count(), 1);
        let begin = unlock_violation_fail_closed(
            &mut seam.daemon,
            &MOCK_NO_UNLOCK_GATE,
            json!(1),
            request_id,
        );
        match begin {
            GateBegin::Final(resp) => assert_eq!(
                resp, r#"{"mockDeny":"rejected"}"#,
                "违例按本门拒绝尾收线（渲染器字节）"
            ),
            other => panic!("违例必须收线为 Final：{other:?}"),
        }
        assert_eq!(
            seam.daemon.shared().approvals.pending_count(),
            0,
            "误登记条目被消费（不残留无主弹窗）"
        );
    }

    /// RePended 契约违例的 **debug 断言半边**（§0 例外脚注「debug 仍断言」
    /// 的字面钉子）：debug 构建下编排器对违例即时断言（release 走
    /// settle_outcome 的 fail-closed 折叠）。
    #[cfg(debug_assertions)]
    #[should_panic(expected = "声明不可 RePended 却返回 RePended")]
    #[test]
    fn orchestrator_asserts_repend_violation_in_debug() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            begin: Some(GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            }),
            finalize_script: VecDeque::from([DeferredOutcome::RePended {
                request_id: uuid::Uuid::new_v4(),
            }]),
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::from([ApprovalDecision::Allowed]));
        let _ = run_deferred(
            &mut seam,
            &MOCK_NONREPEND_GATE,
            M_ITEM_GET,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
    }

    /// 一体化解锁声明违例的 **debug 断言半边**（「debug 仍断言」的字面钉子）。
    #[cfg(debug_assertions)]
    #[should_panic(expected = "声明不支持一体化解锁却登记 needs_unlock 条目")]
    #[test]
    fn orchestrator_asserts_unlock_violation_in_debug() {
        let _guard = MOCK_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_mock(MockGateState {
            begin: Some(GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            }),
            register_needs_unlock: true,
            ..MockGateState::EMPTY
        });
        let mut seam = MockSeam::new(VecDeque::new());
        let _ = run_deferred(
            &mut seam,
            &MOCK_NO_UNLOCK_GATE,
            M_ITEM_GET,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
    }

    /// 注册表完整性（issue #149 验收 1 + issue #150/#167）：策略表
    /// ApprovalDeferred 集合与门声明注册表严格同步——每个审批延迟方法都有
    /// 门声明（可 RePended 仅注入门；一体化解锁支持 = 注入门 + 读通道，
    /// 规则门/写门显式声明 false），每个有门声明的方法都在策略表内；
    /// Inline / OutsideLock 方法无门声明。响应字节的逐门钉住另见
    /// tests/gate_golden.rs（本测试只钉声明布尔，不钉字节）。
    #[test]
    fn flow_registry_matches_strategy_table() {
        let deferred = [
            M_AUTHZ_EVALUATE,
            M_ITEM_GET,
            M_ITEM_EXPORT,
            M_ITEM_PUT,
            M_ITEM_DELETE,
            M_RULE_ADD,
            M_RULE_REMOVE,
        ];
        for m in deferred {
            assert_eq!(
                strategy_of(m),
                ExecutionStrategy::ApprovalDeferred,
                "{m} 应为 ApprovalDeferred"
            );
            let gate = gate_flow(m).unwrap_or_else(|| panic!("{m} 缺门声明"));
            // RePended 声明：仅注入门（锁定态一体化补指纹裁决，#140）。
            assert_eq!(
                gate.rependable,
                m == M_AUTHZ_EVALUATE,
                "{m} RePended 声明不符"
            );
            // 一体化解锁声明（issue #150）：注入门（#67）+ 读通道（#23）
            // 支持；规则门/写门显式无需（产品决策留档）。
            assert_eq!(
                gate.unlock_supported,
                matches!(m, M_AUTHZ_EVALUATE | M_ITEM_GET | M_ITEM_EXPORT),
                "{m} 一体化解锁声明不符"
            );
        }
        // 策略表外的方法无门声明（新增审批门 = 策略表一行 + 注册表一行）。
        for m in [M_SYNC_TRIGGER, M_VAULT_STATUS, M_ITEM_LIST, M_RULE_LIST] {
            assert_ne!(strategy_of(m), ExecutionStrategy::ApprovalDeferred);
            assert!(gate_flow(m).is_none());
        }
    }
}
