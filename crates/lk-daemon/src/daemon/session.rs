//! subscribe / approval.result / 审批超时

use super::*;

impl Daemon {
    /// `subscribe`：会话校验已由 require_session 完成；响应 ok 后传输层把
    /// 连接转入流模式（通知订阅）。
    pub(crate) fn subscribe(&mut self, id: Value) -> RpcResponse {
        RpcResponse::ok(id, json!({}))
    }

    /// `approval.result`：审批回传（决策权始终在 Rust 侧）。调用方限制
    /// （仅桌面内嵌直调）与挑战值校验见 dispatch / [`PendingApprovals::resolve`]：
    /// 伪造 requestId、已超时或**挑战不符** → 忽略（`accepted=false`，
    /// testing.md 第三层 #17/#78）。失败提交写审计（#78：谁在提交审批可
    /// 归因；socket 来源被 `channel.forbidden` 拒绝的审计在 dispatch 拒绝
    /// 分支就地写入；成功提交由第 3 层 finalize 路径审计，不重复记）。
    pub(crate) fn approval_result(
        &mut self,
        id: Value,
        params: Value,
        caller: &CallerId,
    ) -> RpcResponse {
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
        let accepted = self
            .shared
            .approvals
            .resolve(p.request_id, decision, &p.challenge);
        if !accepted {
            // 失败提交审计（伪造/过期/错挑战）：真实桌面回传不会走到这里
            // ——到期竞态除外。starter/channel 取自对端归因（#78）。
            let vault = self.shared.vault.read().unwrap();
            if let Some(v) = vault.as_ref() {
                let _ = self.audit.append(
                    v.keys(),
                    &caller.event("approval.result", AuditResult::Denied),
                );
            }
        }
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
