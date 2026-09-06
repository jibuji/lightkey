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
//! （[`gate_flow`]）声明自己的预检 / begin / finalize / 可否 RePended
//! （[`DeferredFlow`]），编排器只依赖「持命令锁跑一段」与「锁外等一次
//! 决策」两个原语（[`DeferredSeam`]）；RePended 循环内建（锁定态一体化
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
//! 一行 + 门流程模块（各门模块内的流程声明结构体），不抄锁样板。

use std::sync::{Arc, Mutex};

use lk_core::authz::ApprovalDecision;
use lk_core::ipc::*;
use serde_json::Value;

use crate::daemon::gate_kit::{DeferredOutcome, GateBegin};
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
// 审批门流程注册表（issue #149：通用 deferred 编排器的声明面）
// -------------------------------------------------------------------------

/// 审批门流程声明（issue #149）：每个审批延迟方法声明自己的预检 / begin /
/// finalize / 可否 RePended。流程实例为各门模块内的无状态单元结构体
/// （`AuthzFlow` / `DisclosureFlow` / `RuleFlow` / `WriteFlow`），委托既有
/// 门方法；锁编排由 [`run_deferred`] 统一承担。
pub(crate) trait DeferredFlow {
    /// 阶段①预检（命令锁内）：会话/锁态分流（锁态一体化放行 or
    /// fail-closed）。失败 → `session.invalid`，不进 begin。
    fn precheck(&self, daemon: &Daemon, token: Option<&[u8]>) -> bool;

    /// 阶段①（命令锁内）：参数解析 + 裁决分流 + 通道判定；需要审批则
    /// 登记待审并广播 `authz.request`，返回 Pending（等待移出命令锁，G1）。
    fn begin(
        &self,
        daemon: &mut Daemon,
        method: &str,
        id: Value,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin;

    /// 阶段③（重取命令锁）：收决策收尾；返回 [`DeferredOutcome::RePended`]
    /// 表示转二次审批（回到锁外等待）。
    fn finalize(
        &self,
        daemon: &mut Daemon,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> DeferredOutcome;

    /// 可否 RePended（二次审批）：仅注入裁决声明 true（锁定态一体化补
    /// 指纹裁决，issue #140）；声明 false 的流程 finalize 恒 Done。
    fn rependable(&self) -> bool;
}

/// 流程注册表（唯一分发依据）：method → 流程声明。与 [`strategy_of`] 的
/// ApprovalDeferred 集合严格同步（完整性测试钉住，见本模块 tests）；
/// 新增审批门方法 = 此处一行 + 门流程模块。
pub(crate) fn gate_flow(method: &str) -> Option<&'static dyn DeferredFlow> {
    match method {
        M_AUTHZ_EVALUATE => Some(&crate::daemon::authz::AUTHZ_FLOW),
        M_ITEM_GET | M_ITEM_EXPORT => Some(&crate::daemon::disclosure::DISCLOSURE_FLOW),
        M_RULE_ADD | M_RULE_REMOVE => Some(&crate::daemon::rules::RULE_FLOW),
        M_ITEM_PUT | M_ITEM_DELETE => Some(&crate::daemon::write::WRITE_FLOW),
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

/// 通用 deferred 编排器（issue #149）：全部七个审批延迟方法共用同一三阶段
/// 骨架——①命令锁内空闲超时检查 + 预检 + begin（需要审批则登记待审批 +
/// 广播 `authz.request`）→ ②命令锁外等待决策（≤超时默认拒绝；等待期间
/// 其他命令照常服务，G1）→ ③重取命令锁收尾；finalize 返回 RePended 即
/// 回到②（内建循环；仅 `rependable` 流程可能产生，issue #140）。活动
/// 时间戳在收尾（Done）段统一刷新，与常规路径语义一致。
pub(crate) fn run_deferred<S: DeferredSeam>(
    seam: &mut S,
    flow: &dyn DeferredFlow,
    method: &str,
    id: Value,
    token: Option<Vec<u8>>,
    params: Value,
    peer: &PeerInfo,
) -> String {
    // ① 命令锁内：预检失败 → session.invalid（与既有逐门编排一致）
    let begin = seam.locked(|g| {
        g.auto_lock_if_idle();
        if !flow.precheck(g, token.as_deref()) {
            None
        } else {
            Some(flow.begin(g, method, id.clone(), params, peer))
        }
    });
    let Some(begin) = begin else {
        return rpc_string(session_invalid(id));
    };
    match begin {
        GateBegin::Final(resp) => resp,
        GateBegin::Pending { request_id } => {
            let mut request_id = request_id;
            loop {
                // ② 锁外等待（不持命令锁；vault/审批注册表短锁除外，G1）
                let decision = seam.await_decision(request_id);
                // ③ 重取命令锁收尾
                let outcome =
                    seam.locked(
                        |g| match flow.finalize(g, id.clone(), request_id, decision) {
                            DeferredOutcome::Done(r) => {
                                g.touch_activity();
                                DeferredOutcome::Done(r)
                            }
                            other => other,
                        },
                    );
                match outcome {
                    DeferredOutcome::Done(r) => break r,
                    DeferredOutcome::RePended { request_id: next } => {
                        // 可否二次审批由流程声明承载（issue #149）：声明不可
                        // RePended 的流程返回 RePended 属编排契约违反（debug
                        // 构建即断言失败；注册表完整性测试亦钉住 per-method
                        // 声明）。release 下循环照常内建（不可达路径）。
                        debug_assert!(
                            flow.rependable(),
                            "{method} 流程声明不可 RePended 却返回 RePended"
                        );
                        request_id = next;
                    }
                }
            }
        }
    }
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
            let flow = gate_flow(&req.method).expect("策略表与流程注册表同步");
            let token = extract_token(&req.params);
            let mut seam = RouteSeam { state, shared };
            run_deferred(
                &mut seam,
                flow,
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
    // 编排器单测（issue #149）：MockFlow / MockSeam 驱动 run_deferred，
    // 钉三阶段骨架与内建 RePended 循环；真实流程由各门集成测试覆盖。
    // ---------------------------------------------------------------------

    /// Mock 流程：预检开关 + begin 脚本 + finalize 脚本；调用计数收在
    /// 实例字段（并行测试下进程级静态会互相污染）。
    struct MockFlow {
        precheck_ok: bool,
        begin: GateBegin,
        /// finalize 脚本：逐次弹出（耗尽后恒 Done("{}")）。
        finalize_script: Mutex<VecDeque<DeferredOutcome>>,
        precheck_calls: std::sync::atomic::AtomicUsize,
        begin_calls: std::sync::atomic::AtomicUsize,
        finalize_calls: std::sync::atomic::AtomicUsize,
    }

    impl MockFlow {
        fn new(
            precheck_ok: bool,
            begin: GateBegin,
            finalize_script: VecDeque<DeferredOutcome>,
        ) -> Self {
            Self {
                precheck_ok,
                begin,
                finalize_script: Mutex::new(finalize_script),
                precheck_calls: std::sync::atomic::AtomicUsize::new(0),
                begin_calls: std::sync::atomic::AtomicUsize::new(0),
                finalize_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn count(v: &std::sync::atomic::AtomicUsize) -> usize {
            v.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DeferredFlow for MockFlow {
        fn precheck(&self, _daemon: &Daemon, _token: Option<&[u8]>) -> bool {
            self.precheck_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.precheck_ok
        }

        fn begin(
            &self,
            _daemon: &mut Daemon,
            _method: &str,
            _id: Value,
            _params: Value,
            _peer: &PeerInfo,
        ) -> GateBegin {
            self.begin_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match &self.begin {
                GateBegin::Final(resp) => GateBegin::Final(resp.clone()),
                GateBegin::Pending { request_id } => GateBegin::Pending {
                    request_id: *request_id,
                },
            }
        }

        fn finalize(
            &self,
            _daemon: &mut Daemon,
            _id: Value,
            _request_id: uuid::Uuid,
            _decision: ApprovalDecision,
        ) -> DeferredOutcome {
            self.finalize_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.finalize_script
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DeferredOutcome::Done("{}".into()))
        }

        fn rependable(&self) -> bool {
            true
        }
    }

    /// Mock 缝：锁段计数 + 预编程决策队列（耗尽后恒 Denied）；持有一个
    /// 真实 Daemon（tempdir 与实例同生命周期）供编排器触达
    /// auto_lock_if_idle / touch_activity。
    struct MockSeam {
        _dir: tempfile::TempDir,
        daemon: Daemon,
        decisions: Mutex<VecDeque<ApprovalDecision>>,
        lock_segments: std::sync::atomic::AtomicUsize,
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
            }
        }

        fn lock_segments(&self) -> usize {
            self.lock_segments.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DeferredSeam for MockSeam {
        fn locked<R>(&mut self, f: impl FnOnce(&mut Daemon) -> R) -> R {
            self.lock_segments
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            f(&mut self.daemon)
        }

        fn await_decision(&self, _request_id: uuid::Uuid) -> ApprovalDecision {
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
        let flow = MockFlow::new(false, GateBegin::Final("begin".into()), VecDeque::new());
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = run_deferred(
            &mut seam,
            &flow,
            M_AUTHZ_EVALUATE,
            json!(7),
            None,
            json!({}),
            &mock_peer(),
        );
        let parsed: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], json!(ERR_SESSION_INVALID));
        assert_eq!(MockFlow::count(&flow.begin_calls), 0);
        assert_eq!(MockFlow::count(&flow.finalize_calls), 0);
    }

    /// begin 直返 Final → 响应透传，finalize 不执行。
    #[test]
    fn orchestrator_passthrough_final() {
        let flow = MockFlow::new(
            true,
            GateBegin::Final(r#"{"ok":true}"#.into()),
            VecDeque::new(),
        );
        let mut seam = MockSeam::new(VecDeque::new());
        let resp = run_deferred(
            &mut seam,
            &flow,
            M_ITEM_GET,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"ok":true}"#);
        assert_eq!(MockFlow::count(&flow.finalize_calls), 0);
    }

    /// Pending → 锁外等一次决策 → 锁内收尾 Done：三阶段各一段锁。
    #[test]
    fn orchestrator_pending_done_roundtrip() {
        let flow = MockFlow::new(
            true,
            GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            },
            VecDeque::from([DeferredOutcome::Done(r#"{"allowed":true}"#.into())]),
        );
        let mut seam = MockSeam::new(VecDeque::from([ApprovalDecision::Allowed]));
        let resp = run_deferred(
            &mut seam,
            &flow,
            M_ITEM_EXPORT,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"allowed":true}"#);
        // 段①（预检+begin）+ 段③（finalize）= 两段锁；等待在锁外。
        assert_eq!(seam.lock_segments(), 2);
        assert_eq!(MockFlow::count(&flow.finalize_calls), 1);
    }

    /// RePended 循环内建（issue #149 / #140）：finalize 转二次审批 → 回到
    /// 锁外等待 → 二次决策落地后收尾；循环次数由 finalize 脚本承载。
    #[test]
    fn orchestrator_builtin_repend_loop() {
        let next = uuid::Uuid::new_v4();
        let flow = MockFlow::new(
            true,
            GateBegin::Pending {
                request_id: uuid::Uuid::new_v4(),
            },
            VecDeque::from([
                DeferredOutcome::RePended { request_id: next },
                DeferredOutcome::Done(r#"{"allowed":false}"#.into()),
            ]),
        );
        let mut seam = MockSeam::new(VecDeque::from([
            ApprovalDecision::Allowed, // 首次决策 → finalize 转 RePended
            ApprovalDecision::Allowed, // 二次决策 → finalize Done
        ]));
        let resp = run_deferred(
            &mut seam,
            &flow,
            M_AUTHZ_EVALUATE,
            json!(1),
            None,
            json!({}),
            &mock_peer(),
        );
        assert_eq!(resp, r#"{"allowed":false}"#);
        assert_eq!(MockFlow::count(&flow.finalize_calls), 2);
        assert_eq!(seam.lock_segments(), 3);
    }

    /// 注册表完整性（issue #149 验收 1）：策略表 ApprovalDeferred 集合与
    /// 流程注册表严格同步——每个审批延迟方法都有流程声明（可 RePended 仅
    /// 注入门），每个有流程声明的方法都在策略表内；Inline / OutsideLock
    /// 方法无流程声明。
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
            let flow = gate_flow(m).unwrap_or_else(|| panic!("{m} 缺流程声明"));
            // RePended 声明：仅注入门（锁定态一体化补指纹裁决，#140）。
            assert_eq!(flow.rependable(), m == M_AUTHZ_EVALUATE);
        }
        // 策略表外的方法无流程声明（新增审批门 = 策略表一行 + 注册表一行）。
        for m in [M_SYNC_TRIGGER, M_VAULT_STATUS, M_ITEM_LIST, M_RULE_LIST] {
            assert_ne!(strategy_of(m), ExecutionStrategy::ApprovalDeferred);
            assert!(gate_flow(m).is_none());
        }
    }
}
