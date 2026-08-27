//! authz.evaluate 三阶段的锁内两段（阶段① 登记 / 阶段③ 收尾）+ 环境解析 + 审计

use super::rules::VaultRuleView;
use super::*;

impl Daemon {
    /// 阶段①（命令锁内）：会话预检 + 启动者判定 + 第 1/2 层短路；需要审批
    /// 时登记待审批 + 广播 `authz.request`，返回 Pending（等待移出命令锁）。
    pub(crate) fn authz_begin(&mut self, id: Value, params: Value, peer: &PeerInfo) -> AuthzBegin {
        let p: AuthzEvaluateParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => {
                return AuthzBegin::Final(rpc_string(RpcResponse::err(
                    id,
                    ERR_INVALID_PARAMS,
                    "invalid params",
                    None,
                )))
            }
        };
        if let Err(e) = validate_evaluate_fields(&p.command, &p.keys) {
            return AuthzBegin::Final(rpc_string(RpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "invalid params",
                Some(json!({ "detail": e })),
            )));
        }
        let channel = p
            .channel
            .as_deref()
            .map(audit_channel)
            .unwrap_or(AuditChannel::Cli);
        // 启动者判定：守护进程侧从 IPC 对端 PID 回溯（客户端自报字段不信任）
        let starter = derive_starter(peer);
        // cwd 以对端真实 cwd（canonical）为准；客户端自报 cwd 仅作提示（忽略）。
        // 跨命名空间归一化（cross-subsystem.md §7.4，两侧同函数）：WSL UNC /
        // verbatim 形态折算为 `wsl://<distro>/<rest>` 规范形后再做祖先匹配，
        // 与 rule.add 入库基准一致——伪造 cwd 写法变体不得绕过或漏配。
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let req = AuthzRequest {
            starter,
            cwd,
            command: p.command,
            keys: p.keys,
        };
        let shared = Arc::clone(&self.shared);
        let vault = shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return AuthzBegin::Final(
                serde_json::to_string(&session_invalid(id)).unwrap_or_else(|_| "{}".into()),
            );
        };
        // 单次扫描 secret 索引（批量解析请求 key；避免逐 key 全表扫描）
        let secrets = v.secret_values().unwrap_or_default();
        let result = self
            .gate
            .evaluate_layers(&req, &VaultRuleView { vault: v, secrets });
        drop(vault);
        match result {
            LayerResult::Allowed { keys } => {
                // 第 2 层命中：解密注入值 + 审计 allowed（caller channel）
                match self.resolve_env(&keys) {
                    Ok(env) => {
                        self.audit_authz(&req, channel, AuditResult::Allowed);
                        AuthzBegin::Final(rpc_string(RpcResponse::ok(
                            id,
                            serde_json::to_value(AuthzEvaluateResult {
                                allowed: true,
                                reason: None,
                                env: Some(env),
                            })
                            .unwrap_or(Value::Null),
                        )))
                    }
                    Err(e) => AuthzBegin::Final(rpc_string(self.err_response(id, &e))),
                }
            }
            LayerResult::Denied { reason } => {
                // 第 1 层：拒绝（不弹窗、不留内容，仅审计拒绝事件）
                self.audit_authz(&req, channel, AuditResult::Denied);
                AuthzBegin::Final(rpc_string(RpcResponse::ok(
                    id,
                    serde_json::to_value(AuthzEvaluateResult {
                        allowed: false,
                        reason: Some(reason.as_str().to_string()),
                        env: None,
                    })
                    .unwrap_or(Value::Null),
                )))
            }
            LayerResult::NeedsApproval => {
                // 第 3 层：无审批界面 → fail-closed 立即拒绝（不阻塞）
                if !self.gate.approval().available() {
                    self.audit_authz(&req, channel, AuditResult::Denied);
                    return AuthzBegin::Final(rpc_string(RpcResponse::ok(
                        id,
                        serde_json::to_value(AuthzEvaluateResult {
                            allowed: false,
                            reason: Some(DenyReason::NoUi.as_str().to_string()),
                            env: None,
                        })
                        .unwrap_or(Value::Null),
                    )));
                }
                // 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）
                let request_id = lk_core::crypto::random_uuid();
                let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
                let areq = ApprovalRequest {
                    request_id,
                    starter: req.starter.clone(),
                    project_dir: req.cwd.clone(),
                    command: req.command.clone(),
                    keys: req.keys.clone(),
                };
                self.gate.approval().open(&areq, expires_at);
                self.pending_authz
                    .lock()
                    .unwrap()
                    .insert(request_id, PendingAuthz { request: req });
                AuthzBegin::Pending { request_id }
            }
        }
    }

    /// 阶段③（重取命令锁）：收决策 → 解密 key 值 → 审计（channel=Approval）
    /// → 返回。等待期间锁定 → `session.invalid`（无法解密/审计）。
    pub(crate) fn authz_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let pending = self.pending_authz.lock().unwrap().remove(&request_id);
        let Some(pending) = pending else {
            // 条目已被消费（极端竞态）→ 保守拒绝
            return rpc_string(RpcResponse::ok(
                id,
                serde_json::to_value(AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Rejected.as_str().to_string()),
                    env: None,
                })
                .unwrap_or(Value::Null),
            ));
        };
        let result = match decision {
            ApprovalDecision::Allowed => {
                match self.resolve_env(&pending.request.keys) {
                    Ok(env) => {
                        self.audit_authz(
                            &pending.request,
                            AuditChannel::Approval,
                            AuditResult::Allowed,
                        );
                        AuthzEvaluateResult {
                            allowed: true,
                            reason: None,
                            env: Some(env),
                        }
                    }
                    Err(_) => {
                        // 等待期间锁定/密钥不可用 → 无法满足
                        return serde_json::to_string(&session_invalid(id))
                            .unwrap_or_else(|_| "{}".into());
                    }
                }
            }
            ApprovalDecision::Denied => {
                self.audit_authz(
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Rejected.as_str().to_string()),
                    env: None,
                }
            }
            ApprovalDecision::Timeout => {
                self.audit_authz(
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Timeout,
                );
                AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Timeout.as_str().to_string()),
                    env: None,
                }
            }
        };
        rpc_string(RpcResponse::ok(
            id,
            serde_json::to_value(result).unwrap_or(Value::Null),
        ))
    }

    /// 解析注入 env（vault 读锁内；key 名 → 值；仅被授权 key；单次扫描）。
    pub(crate) fn resolve_env(
        &self,
        keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, String>> {
        let vault = self.shared.vault.read().unwrap();
        let v = vault.as_ref().ok_or(Error::SessionInvalid)?;
        let all = v.secret_values()?;
        let mut env = std::collections::BTreeMap::new();
        for k in keys {
            if let Some(value) = all.get(k) {
                env.insert(k.clone(), value.clone());
            }
        }
        Ok(env)
    }

    /// 授权路径审计（starter 为进程链回溯结果；command 为命令摘要，脱敏：
    /// `lk inject <sha256:8>`，audit.md §2）。
    pub(crate) fn audit_authz(
        &self,
        req: &AuthzRequest,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        let digest = sha2::Sha256::digest(req.command.as_bytes());
        let short: String = hex::encode(&digest[..4]);
        let target = req
            .command
            .split_whitespace()
            .next()
            .unwrap_or("lk")
            .to_string();
        let vault = self.shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return; // 已锁定 → 无法签名（K_audit 已擦除）
        };
        let keys = v.keys().clone();
        drop(vault);
        let _ = self.audit.append(
            &keys,
            &EventInput {
                starter: req.starter.clone(),
                target,
                command: format!("lk inject <{short}>"),
                result,
                channel,
                old_key_id: None,
                new_key_id: None,
            },
        );
    }
}

/// 阶段① 结果：最终响应（不阻塞）或待审批（等待移出命令锁）。
/// 到期时刻以登记值为准（审批注册表侧超时默认拒绝），此处不重复携带。
pub(crate) enum AuthzBegin {
    Final(String),
    Pending { request_id: uuid::Uuid },
}
