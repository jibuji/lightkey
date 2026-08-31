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
//! - [`ExecutionStrategy::ApprovalDeferred`]：命令锁内 begin → **锁外**等待
//!   审批决策（≤超时默认拒绝）→ 重取命令锁收尾（`authz.evaluate`；
//!   G1 回归教训：等待不持有命令锁）。
//!
//! 两条缝共用同一张策略表（interface 即测试面）：
//!
//! - [`route`]（主缝）：生产（CLI socket / 桌面内嵌）与并发回归测试的唯一
//!   入口；按策略编排加锁/解锁窗口；
//! - [`Daemon::handle`](crate::Daemon::handle)（直调）：签名不变，查同一张
//!   表；Inline 行为不变；两阶段策略复用同一组 phase 方法顺序执行（调用方
//!   已持命令锁，无解锁窗口可释放——单线程直调下锁窗口本就不可观察，
//!   请求/响应与主缝一致）。测试 setup 与请求/响应等价性断言走这里。
//!
//! 新增 RPC 方法 = 在 [`strategy_of`] 登记（新方法默认 Inline，两阶段的
//! 显式声明策略），不抄锁样板。

use std::sync::{Arc, Mutex};

use lk_core::ipc::*;
use serde_json::Value;

use crate::transport::PeerInfo;
use crate::{extract_token, rpc_string, Daemon, SharedDaemon};

/// RPC 方法的执行策略（锁纪律声明；见模块文档）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStrategy {
    /// 命令锁内跑完。
    Inline,
    /// 锁内预检 → 锁外工作 → 锁内收尾（`sync.trigger`）。
    OutsideLock,
    /// 锁内 begin → 锁外等待审批 → 锁内收尾（`authz.evaluate`）。
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
pub fn strategy_of(method: &str) -> ExecutionStrategy {
    match method {
        M_SYNC_TRIGGER => ExecutionStrategy::OutsideLock,
        M_AUTHZ_EVALUATE | M_ITEM_GET | M_ITEM_EXPORT | M_RULE_ADD | M_RULE_REMOVE => {
            ExecutionStrategy::ApprovalDeferred
        }
        _ => ExecutionStrategy::Inline,
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
        Some(ExecutionStrategy::ApprovalDeferred) => approval_deferred(state, shared, line, peer),
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

/// ApprovalDeferred 编排（`authz.evaluate` / `item.get` / `item.export` /
/// `rule.add` / `rule.remove`）：①命令锁内 begin（会话预检 + 通道判定 +
/// 第 1/2 层短路；需要审批则登记待审批并广播 `authz.request`）→ ②命令锁外
/// 等待决策（≤超时默认拒绝；等待期间其他命令照常服务，G1）→ ③重取命令锁
/// 收尾。
///
/// 按 method 分派到各自的 begin/finalize 对：`authz.evaluate` 走注入裁决
/// （`authz_begin` / `authz_finalize`），`item.get` / `item.export` 走值披露
/// 裁决（`disclosure_begin` / `disclosure_finalize`，daemon/disclosure.rs），
/// `rule.add` / `rule.remove` 走规则管理审批门（`rule_begin` /
/// `rule_finalize`，daemon/rules.rs，补充拍板 #22）。
fn approval_deferred(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    line: &str,
    peer: &PeerInfo,
) -> String {
    let req: RpcRequest = serde_json::from_str(line).expect("route 已按策略分派");
    if req.method == M_AUTHZ_EVALUATE {
        authz_evaluate_deferred(state, shared, &req, peer)
    } else if req.method == M_RULE_ADD || req.method == M_RULE_REMOVE {
        rule_deferred(state, shared, &req, peer)
    } else {
        disclosure_deferred(state, shared, &req, peer)
    }
}

/// 注入裁决编排（`authz.evaluate`；三阶段见 `authz_evaluate_deferred` 原语义）：
/// ①命令锁内 begin（会话预检 + 启动者判定 + 第 1/2 层短路；需要审批则登记
/// 待审批并广播 `authz.request`）→ ②命令锁外等待决策（≤超时默认拒绝；等待
/// 期间其他命令照常服务，G1）→ ③重取命令锁收尾（解密 key 值 + 审计
/// channel=Approval）。
fn authz_evaluate_deferred(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    req: &RpcRequest,
    peer: &PeerInfo,
) -> String {
    let id = req.id.clone();
    let token = extract_token(&req.params);
    // ① 命令锁内
    let begin = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        // #67：锁态 + 桌面审批界面在场 → 放行至 authz_begin 走一体化
        // （headless 锁态仍 fail-closed session.invalid）
        if !guard.authz_evaluate_precheck(token.as_deref()) {
            return rpc_string(session_invalid(id));
        }
        guard.authz_begin(id.clone(), req.params.clone(), peer)
    };
    match begin {
        crate::AuthzBegin::Final(resp) => Some(resp),
        crate::AuthzBegin::Pending { request_id, .. } => {
            // ② 锁外等待（不持命令锁；vault/审批注册表短锁除外）
            let decision = shared.approvals.await_decision(request_id);
            // ③ 重取命令锁收尾
            let resp = {
                let mut guard = state.lock().expect("daemon mutex poisoned");
                let r = guard.authz_finalize(id, request_id, decision);
                guard.touch_activity();
                r
            };
            Some(resp)
        }
    }
    .unwrap_or_else(|| "{}".into())
}

/// 值披露编排（`item.get` / `item.export`，M2.9）：同一三阶段骨架——
/// ①命令锁内 `disclosure_begin`（会话预检 + 条目解析 + 通道判定：desktop
/// 直调受信豁免直返；socket 走读规则匹配 → 命中静默放行，未命中弹窗/拒绝）
/// → ②命令锁外等待决策 → ③重取命令锁收尾（披露值/数据包 + 审计）。
fn disclosure_deferred(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    req: &RpcRequest,
    peer: &PeerInfo,
) -> String {
    let id = req.id.clone();
    let token = extract_token(&req.params);
    // ① 命令锁内：锁态先失败（session.invalid，spec §3——读通道不做 #67
    // 式一体化，§12）
    let begin = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        if !guard.disclosure_precheck(token.as_deref()) {
            return rpc_string(session_invalid(id));
        }
        guard.disclosure_begin(id.clone(), &req.method, req.params.clone(), peer)
    };
    match begin {
        crate::DisclosureBegin::Final(resp) => Some(resp),
        crate::DisclosureBegin::Pending { request_id } => {
            // ② 锁外等待（≤超时默认拒绝；G1）
            let decision = shared.approvals.await_decision(request_id);
            // ③ 重取命令锁收尾
            let resp = {
                let mut guard = state.lock().expect("daemon mutex poisoned");
                let r = guard.disclosure_finalize(id, request_id, decision);
                guard.touch_activity();
                r
            };
            Some(resp)
        }
    }
    .unwrap_or_else(|| "{}".into())
}

/// 规则管理审批门编排（`rule.add` / `rule.remove`，补充拍板 #22）：同一
/// 三阶段骨架——①命令锁内 `rule_begin`（会话/锁态预检 + 参数校验/归一化 +
/// 通道判定：desktop 直调受信豁免直返；socket 走 fail-closed 检查后登记 +
/// 广播）→ ②命令锁外等待决策 → ③重取命令锁收尾（TOCTOU 锁内重校验后
/// 落盘 + 审计，daemon/rules.rs）。
fn rule_deferred(
    state: &Arc<Mutex<Daemon>>,
    shared: &Arc<SharedDaemon>,
    req: &RpcRequest,
    peer: &PeerInfo,
) -> String {
    let id = req.id.clone();
    let token = extract_token(&req.params);
    // ① 命令锁内：锁态先失败（session.invalid——规则在加密库内）
    let begin = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        if !guard.rule_precheck(token.as_deref()) {
            return rpc_string(session_invalid(id));
        }
        guard.rule_begin(id.clone(), &req.method, req.params.clone(), peer)
    };
    match begin {
        crate::RuleBegin::Final(resp) => Some(resp),
        crate::RuleBegin::Pending { request_id } => {
            // ② 锁外等待（≤超时默认拒绝；G1）
            let decision = shared.approvals.await_decision(request_id);
            // ③ 重取命令锁收尾
            let resp = {
                let mut guard = state.lock().expect("daemon mutex poisoned");
                let r = guard.rule_finalize(id, request_id, decision);
                guard.touch_activity();
                r
            };
            Some(resp)
        }
    }
    .unwrap_or_else(|| "{}".into())
}
