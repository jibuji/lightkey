//! subscribe / approval.result / 审批超时

use super::*;

impl Daemon {
    /// `subscribe`：会话校验已由 require_session 完成；响应 ok 后传输层把
    /// 连接转入流模式（通知订阅）。
    pub(crate) fn subscribe(&mut self, id: Value) -> RpcResponse {
        RpcResponse::ok(id, json!({}))
    }

    /// `approval.result`：审批回传（决策权始终在 Rust 侧）。伪造/已超时的
    /// requestId → 忽略（`accepted=false`，testing.md 第三层 #17）。
    pub(crate) fn approval_result(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ApprovalResultParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let decision = match p.decision.as_str() {
            "allowed" => ApprovalDecision::Allowed,
            "denied" => ApprovalDecision::Denied,
            _ => {
                return RpcResponse::err(
                    id,
                    ERR_INVALID_PARAMS,
                    "invalid params",
                    Some(json!({ "detail": "decision 须为 allowed | denied" })),
                )
            }
        };
        let accepted = self.shared.approvals.resolve(p.request_id, decision);
        let result = ApprovalResultOutcome { accepted };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    /// 审批超时（config 可配；默认 30s，第 3 层超时默认拒绝）。
    pub(crate) fn approval_timeout(&self) -> u64 {
        self.shared
            .config
            .read()
            .unwrap()
            .approval_timeout_secs
            .max(1)
    }

    /// 活动时间戳收尾（两阶段策略的锁内第③阶段；与常规路径语义一致）。
    pub(crate) fn touch_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}
