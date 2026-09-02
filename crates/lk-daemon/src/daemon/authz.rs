//! authz.evaluate 三阶段的锁内两段（阶段① 登记 / 阶段③ 收尾）+ 环境解析 + 审计

use super::rules::VaultRuleView;
use super::*;
use lk_core::authz::FingerprintMismatch;

/// M2.98 绑定规则指纹裁决结果（§5.2）：`authz_begin` 第 2 层命中后追加判定。
enum FingerprintVerdict {
    /// 无绑定规则命中（沿现状语义放行）。
    NotApplicable,
    /// 绑定规则且指纹匹配 → 静默放行。
    Allowed,
    /// 绑定规则指纹失配/候选不可解析 → 视同未命中 → 转审批（携带失配展示）。
    NeedsApproval(Option<FingerprintMismatch>),
}

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
        let channel = client_channel(p.channel.as_deref(), peer_channel(peer));
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
            // 锁定态（#67）：桌面审批界面在场 → 一体化解锁+审批；否则沿旧
            // 行为 fail-closed `session.invalid`（headless，CLI 提示先解锁）。
            // 锁态无法裁决规则项（规则在加密 vault 内）：只做不依赖 vault
            // 的第 1 层 fail-closed（unknown starter / 无 cwd），其余裁决
            // 全部推迟到弹窗批准 + 临时解锁之后的 finalize（届时使用临时
            // vault 跑完整三层，见 authz_finalize）。unknown starter 不弹窗
            // （fail-closed 不打扰用户、不留内容；锁态无 K_audit 无法审计，
            // 与 v0 锁态 session.invalid 同口径）。
            if req.starter == UNKNOWN_STARTER {
                return AuthzBegin::Final(rpc_string(RpcResponse::ok(
                    id,
                    serde_json::to_value(AuthzEvaluateResult {
                        allowed: false,
                        reason: Some(DenyReason::UnknownStarter.as_str().to_string()),
                        env: None,
                    })
                    .unwrap_or(Value::Null),
                )));
            }
            if req.cwd.is_empty() {
                return AuthzBegin::Final(rpc_string(RpcResponse::ok(
                    id,
                    serde_json::to_value(AuthzEvaluateResult {
                        allowed: false,
                        reason: Some(DenyReason::NoCwd.as_str().to_string()),
                        env: None,
                    })
                    .unwrap_or(Value::Null),
                )));
            }
            // 无审批界面（纯 headless 守护进程）→ fail-closed（issue #67：
            // GUI 不在运行维持现状直接拒绝，不阻塞、不静默回落）
            if !self.gate.approval().available() {
                return AuthzBegin::Final(
                    serde_json::to_string(&session_invalid(id)).unwrap_or_else(|_| "{}".into()),
                );
            }
            // 登记待审批（needs_unlock=true）+ 广播 authz.request
            // （needsUnlock=true，D 层弹窗须同时展示主密码输入与授权栏）。
            // challenge 语义不变：一次性应答值，仅投递桌面订阅者（#78）。
            drop(vault);
            let request_id = lk_core::crypto::random_uuid();
            let challenge = hex::encode(lk_core::crypto::random_array::<16>());
            let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
            let areq = ApprovalRequest {
                request_id,
                starter: req.starter.clone(),
                project_dir: req.cwd.clone(),
                command: req.command.clone(),
                keys: req.keys.clone(),
                challenge: challenge.clone(),
                needs_unlock: true,
                kind: lk_core::authz::ApprovalKind::Inject,
                export_meta: None,
                // 锁态：规则在加密 vault 内无指纹可比（须待解锁后 finalize），
                // 审批帧不携带失配信息。
                fingerprint_mismatch: None,
            };
            self.gate.approval().open(&areq, expires_at);
            self.pending_authz.lock().unwrap().insert(
                request_id,
                PendingAuthz {
                    request: req,
                    needs_unlock: true,
                    temp_vault: None,
                },
            );
            return AuthzBegin::Pending { request_id };
        };
        // 单次扫描 secret 索引（批量解析请求 key；避免逐 key 全表扫描）
        let secrets = v.secret_values().unwrap_or_default();
        let result = self
            .gate
            .evaluate_layers(&req, &VaultRuleView { vault: v, secrets });
        // M2.98 程序指纹绑定：第 2 层命中但绑定规则指纹失配 → 视同未命中
        // （identity-binding.md §3/§5）。需在 vault 读锁内判定（规则在库内）。
        let fp_verdict = self.fingerprint_adjudicate(&req, peer, v);
        drop(vault);
        match result {
            LayerResult::Allowed { keys } => {
                // 绑定规则指纹失配 → 折叠为 NeedsApproval（弹窗「指纹不符」/headless
                // 统一 authz.denied，与未命中同码、防探测）。
                if let FingerprintVerdict::NeedsApproval(mismatch) = fp_verdict {
                    return self.open_inject_approval(id, req, channel, false, mismatch);
                }
                // 第 2 层命中（且无绑定失配）：解密注入值 + 审计 allowed
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
            LayerResult::NeedsApproval =>
            // 第 3 层：登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）；
            // 无审批界面 → fail-closed 立即拒绝（不阻塞）。
            {
                self.open_inject_approval(id, req, channel, false, None)
            }
        }
    }

    /// M2.98 程序指纹裁决（绑定规则命中命令形态但指纹不符 → 视同未命中，
    /// identity-binding.md §3/§5.2）。在 vault 读锁内调用（规则在库内）。
    ///
    /// - **desktop 内嵌直调受信豁免**（§3：`pid=0` → 不查指纹）；
    /// - 无绑定规则命中 → NotApplicable（沿现状语义放行）；
    /// - 候选解析失败（对端 env 不可读 / PATH+cwd 未命中 / stat/hash 失败）→
    ///   NeedsApproval(None)（视同未命中 + 无可解析路径展示）。
    fn fingerprint_adjudicate(
        &mut self,
        req: &AuthzRequest,
        peer: &PeerInfo,
        v: &UnlockedVault,
    ) -> FingerprintVerdict {
        // desktop 内嵌直调：pid=0，无对端 env 可读 → 受信豁免不查指纹。
        if peer.pid == 0 {
            return FingerprintVerdict::NotApplicable;
        }
        // 命中命令形态的绑定 inject 规则（capability=inject + 项目祖先 + command 形态）。
        let bound: Vec<lk_core::model::ProgramFingerprint> = match v.list_rules() {
            Ok(rules) => rules
                .into_iter()
                .filter(|r| {
                    r.fingerprint.is_some()
                        && lk_core::authz::rule_matches(r, &req.cwd, &req.command)
                })
                .map(|r| r.fingerprint.unwrap())
                .collect(),
            Err(_) => return FingerprintVerdict::NotApplicable, // 规则库损坏由第 1 层已拒
        };
        if bound.is_empty() {
            return FingerprintVerdict::NotApplicable;
        }
        // 对端真实 cwd 兜底（peer.cwd 已是真实值；绝对命令免 PATH 解析）。
        let cwd = peer.cwd.clone().unwrap_or_else(|| req.cwd.clone());
        match crate::identity::adjudicate_binding(
            self.peer_env.as_ref(),
            peer.pid,
            &cwd,
            &req.command,
            &bound,
            &mut self.fingerprint_cache,
        ) {
            crate::identity::BindingOutcome::Allowed => FingerprintVerdict::Allowed,
            crate::identity::BindingOutcome::Mismatch(m) => {
                FingerprintVerdict::NeedsApproval(Some(m))
            }
            crate::identity::BindingOutcome::Unresolved => FingerprintVerdict::NeedsApproval(None),
        }
    }

    /// 注入审批的统一入口（解锁态 NeedsApproval 与指纹失配折叠共用）：登记
    /// 待审批 + 广播 `authz.request`（命令锁内、非阻塞）。无审批界面 → 审计
    /// 拒绝 + fail-closed 立即拒绝（与未命中同码、防探测）。
    fn open_inject_approval(
        &mut self,
        id: Value,
        req: AuthzRequest,
        channel: AuditChannel,
        needs_unlock: bool,
        fingerprint_mismatch: Option<FingerprintMismatch>,
    ) -> AuthzBegin {
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
        // challenge：一次性审批应答值（#78 方案 B），仅经通知桥投给桌面订阅者；
        // 回传必须原样带回（resolve 逐一比对）。
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let areq = ApprovalRequest {
            request_id,
            starter: req.starter.clone(),
            project_dir: req.cwd.clone(),
            command: req.command.clone(),
            keys: req.keys.clone(),
            challenge: challenge.clone(),
            needs_unlock,
            kind: lk_core::authz::ApprovalKind::Inject,
            export_meta: None,
            fingerprint_mismatch,
        };
        self.gate.approval().open(&areq, expires_at);
        self.pending_authz.lock().unwrap().insert(
            request_id,
            PendingAuthz {
                request: req,
                needs_unlock,
                temp_vault: None,
            },
        );
        AuthzBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁）：收决策 → 解密 key 值 → 审计（channel=Approval）
    /// → 返回。等待期间锁定 → `session.invalid`（无法解密/审计）。
    ///
    /// **锁定态一体化（#67）**：`pending.needs_unlock` 时，`Allowed` 决策
    /// 使用审批回传时已临时解锁的 vault（`temp_vault`，approval_result 存
    /// 入）：在临时 vault 上跑完整三层（第 1/2 层锁态无法预载——规则在
    /// 加密库内）+ 解析 env + 审计（用临时 vault 的 K_audit），随后临时
    /// vault 随条目销毁——**不置 shared.vault / 不签发令牌 / 不写
    /// session.token**（#67 关键约束：本次注入不产生 item.* 全量能力，#65）。
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
        if pending.needs_unlock {
            return self.authz_finalize_unlock(id, pending, decision);
        }
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

    /// 锁定态一体化 finalize（#67，见 [`Self::authz_finalize`]）。
    fn authz_finalize_unlock(
        &mut self,
        id: Value,
        pending: PendingAuthz,
        decision: ApprovalDecision,
    ) -> String {
        let req = &pending.request;
        match decision {
            ApprovalDecision::Allowed => {
                // 临时 vault 由 approval_result 以正确主密码解锁后存入；
                // 缺失（异常路径）→ 保守拒绝
                let Some(vault) = pending.temp_vault else {
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
                // 完整三层裁决（锁态 begin 无法预载规则/解析 key；解锁后
                // 一次性在临时 vault 上跑：第 1/2 层短路、未命中则第 3 层
                // 已由弹窗批准视同通过）
                let secrets = vault.secret_values().unwrap_or_default();
                let layer = self.gate.evaluate_layers(
                    req,
                    &VaultRuleView {
                        vault: &vault,
                        secrets,
                    },
                );
                let result = match layer {
                    LayerResult::Allowed { keys } => match self.resolve_env_from(&vault, &keys) {
                        Ok(env) => {
                            self.audit_authz_from(
                                &vault,
                                req,
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
                            return serde_json::to_string(&session_invalid(id))
                                .unwrap_or_else(|_| "{}".into())
                        }
                    },
                    LayerResult::Denied { reason } => {
                        self.audit_authz_from(
                            &vault,
                            req,
                            AuditChannel::Approval,
                            AuditResult::Denied,
                        );
                        AuthzEvaluateResult {
                            allowed: false,
                            reason: Some(reason.as_str().to_string()),
                            env: None,
                        }
                    }
                    // 未命中规则：第 3 层弹窗已批准（allowed 决策即批准）
                    LayerResult::NeedsApproval => match self.resolve_env_from(&vault, &req.keys) {
                        Ok(env) => {
                            self.audit_authz_from(
                                &vault,
                                req,
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
                            return serde_json::to_string(&session_invalid(id))
                                .unwrap_or_else(|_| "{}".into())
                        }
                    },
                };
                // 临时 vault 随本函数结束 drop——临时解锁态销毁（未置
                // shared.vault，vault 仍锁定；无会话令牌、无 token 文件）
                rpc_string(RpcResponse::ok(
                    id,
                    serde_json::to_value(result).unwrap_or(Value::Null),
                ))
            }
            // 拒绝/超时：未解锁（无临时 vault）→ 无 K_audit 可签名，审计
            // 不可写（与 v0 锁态拒绝同口径——fail-closed 不留审计内容）
            ApprovalDecision::Denied => rpc_string(RpcResponse::ok(
                id,
                serde_json::to_value(AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Rejected.as_str().to_string()),
                    env: None,
                })
                .unwrap_or(Value::Null),
            )),
            ApprovalDecision::Timeout => rpc_string(RpcResponse::ok(
                id,
                serde_json::to_value(AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Timeout.as_str().to_string()),
                    env: None,
                })
                .unwrap_or(Value::Null),
            )),
        }
    }

    /// 解析注入 env（vault 读锁内；key 名 → 值；仅被授权 key；单次扫描）。
    pub(crate) fn resolve_env(
        &self,
        keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, String>> {
        let vault = self.shared.vault.read().unwrap();
        let v = vault.as_ref().ok_or(Error::SessionInvalid)?;
        self.resolve_env_from(v, keys)
    }

    /// 从指定 vault（临时解锁态，#67）解析注入 env；语义同
    /// [`Self::resolve_env`]——仅被授权 key、单次扫描。
    pub(crate) fn resolve_env_from(
        &self,
        v: &UnlockedVault,
        keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, String>> {
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
    /// `lk inject <sha256:8>`，audit.md §2）。签名用共享 vault 的 K_audit。
    pub(crate) fn audit_authz(
        &self,
        req: &AuthzRequest,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        let vault = self.shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return; // 已锁定 → 无法签名（K_audit 已擦除）
        };
        self.audit_authz_with_keys(&v.keys().clone(), req, channel, result);
    }

    /// 授权路径审计的变体：用**指定 vault**（锁定态一体化的临时 vault，#67）
    /// 的 K_audit 签名——锁态 `shared.vault` 为空，但临时解锁后 K_audit
    /// 在内存可用（不落盘、不签发令牌，仅本次注入）。字段语义同
    /// [`Self::audit_authz`]。
    pub(crate) fn audit_authz_from(
        &self,
        vault: &UnlockedVault,
        req: &AuthzRequest,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        self.audit_authz_with_keys(&vault.keys().clone(), req, channel, result);
    }

    fn audit_authz_with_keys(
        &self,
        keys: &lk_core::crypto::Keys,
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
        let _ = self.audit.append(
            keys,
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
