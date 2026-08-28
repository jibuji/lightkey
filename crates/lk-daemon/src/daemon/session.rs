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
    ///
    /// **锁定态一体化（#67）**：待审条目带 `needs_unlock` 时，`allowed`
    /// 决策必须携带 `masterPassword`——先做**临时解锁**（AuthGuard 限流
    /// 照常生效、审计 `vault.unlock`），解锁成功才把临时 vault 存入待审
    /// 条目并 `resolve(Allowed)`（finalize 消费后即销毁临时态，不签发会话
    /// 令牌）；主密码错误 → 错误响应退回弹窗（条目保留，倒计时内可重试）。
    /// denied 决策无需主密码（未解锁也写不了审计——锁态无 K_audit，
    /// 与 v0 headless 拒绝同口径不审计）。
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
        // 锁定态一体化（#67）：allowed 需先临时解锁（主密码），失败不回传
        // 决策——错误响应让弹窗停留，倒计时内可重试（AuthGuard 防暴破）。
        if decision == ApprovalDecision::Allowed
            && self
                .pending_authz
                .lock()
                .unwrap()
                .get(&p.request_id)
                .map(|e| e.needs_unlock)
                .unwrap_or(false)
        {
            return self.approval_result_unlock(id, p, caller);
        }
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

    /// 锁定态一体化审批的 `allowed` 分支（#67）：AuthGuard 限流 → 主密码
    /// 临时解锁 → 审计 `vault.unlock`（via=inject-gui，channel=desktop）→
    /// 临时 vault 存入待审条目 → `resolve(Allowed)` 唤醒 CLI。主密码错误 →
    /// 错误响应（弹窗显示「解锁失败」，条目保留可重试）；被限流 →
    /// `ERR_RATE_LIMITED`（AuthGuard 不绕过，issue #67 约束 #5）。
    fn approval_result_unlock(
        &mut self,
        id: Value,
        p: ApprovalResultParams,
        caller: &CallerId,
    ) -> RpcResponse {
        // 解锁限流照常生效（与 vault.unlock 同一 AuthGuard）
        if let Some(retry) = self.unlock_guard.check() {
            return RpcResponse::err(
                id,
                ERR_RATE_LIMITED,
                MSG_RATE_LIMITED,
                Some(json!({ "retryAfterSeconds": retry })),
            );
        }
        // 解锁 + 校验主密码（错误密码不 resolve，条目保留供弹窗重试）
        let Some(pw) = p.master_password.as_deref() else {
            return RpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "invalid params",
                Some(json!({ "detail": "锁定态审批 allowed 需要 masterPassword" })),
            );
        };
        match UnlockedVault::unlock(&self.shared.dir, pw) {
            Ok(vault) => {
                self.unlock_guard.on_success();
                // 审计 vault.unlock（via=inject-gui 一体化；channel 按桌面
                // 直调归因 #66——starter/channel 取 desktop）。锁态无会话，
                // 但临时临时 vault 持 K_audit 可签名。
                let _ = self.audit.append(
                    vault.keys(),
                    &caller.event("vault.unlock", AuditResult::Allowed),
                );
                // 临时 vault 存入待审条目（authz_finalize 消费后即销毁；
                // 不置 shared.vault、不签发令牌、不写 session.token）
                self.pending_authz
                    .lock()
                    .unwrap()
                    .get_mut(&p.request_id)
                    .expect("needs_unlock 条目在 dispatch 已确认存在")
                    .temp_vault = Some(vault);
                let accepted = self.shared.approvals.resolve(
                    p.request_id,
                    ApprovalDecision::Allowed,
                    &p.challenge,
                );
                let result = ApprovalResultOutcome { accepted };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(_) => {
                // 主密码错误/库未初始化：统一文案（防探测，与 vault.unlock
                // 同策略）；不 resolve——弹窗保留、AuthGuard 记失败计数
                self.unlock_guard.on_failure();
                RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None)
            }
        }
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
