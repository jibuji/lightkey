//! authz.evaluate 三阶段的锁内两段（阶段① 登记 / 阶段③ 收尾）+ 环境解析 + 审计
//!
//! 五件套下沉（issue #148）：begin 结果类型（[`GateBegin`]）、统一待审批
//! 注册表（[`GateEntry`]，needs_unlock / 审批工作区条目级承载，issue
//! #150）、审批请求单点铸造（[`Daemon::open_gate_approval`]）、审计辅助
//! （[`Daemon::audit_gate`]，按「本次执行所用 vault」签名）、参数解析辅助
//! 均出自 daemon/gate_kit.rs；本模块保留 authz 特有的裁决编排与审计事件
//! 摘要（`lk inject <sha256:8>` 脱敏）。

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
    /// 返回**分层裁决结果**（issue #167）：拒绝以 reason 承载（字节由门
    /// 声明渲染器唯一渲染），放行/协议直返为已渲染负载。
    pub(crate) fn authz_begin(
        &mut self,
        _method: &str,
        id: Value,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin {
        let p: AuthzEvaluateParams = match parse_gate_params(&id, params) {
            Ok(p) => p,
            Err(line) => return GateBegin::Final(line),
        };
        if let Err(e) = validate_evaluate_fields(&p.command, &p.keys) {
            return GateBegin::Final(invalid_params(id, Some(e)));
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
            // 行为 fail-closed `session.invalid`（headless，CLI 提示先解锁）
            // ——会话前置失败（执行层），不是裁决拒绝，不经渲染器（分层见
            // gate_kit.rs `GateBegin` 类型文档）。锁态无法裁决规则项（规则
            // 在加密 vault 内）：只做不依赖 vault 的第 1 层 fail-closed
            // （unknown starter / 无 cwd），其余裁决全部推迟到弹窗批准 +
            // 临时解锁之后的 finalize（届时使用临时 vault 跑完整三层，见
            // authz_finalize）。unknown starter 不弹窗（fail-closed 不打扰
            // 用户、不留内容；锁态无 K_audit 无法审计，与 v0 锁态
            // session.invalid 同口径）。
            if req.starter == UNKNOWN_STARTER {
                return GateBegin::Deny(GateDeny::UnknownStarter);
            }
            if req.cwd.is_empty() {
                return GateBegin::Deny(GateDeny::NoCwd);
            }
            // 无审批界面（纯 headless 守护进程）→ fail-closed（issue #67：
            // GUI 不在运行维持现状直接拒绝，不阻塞、不静默回落）
            if !self.approval_available() {
                return GateBegin::Final(rpc_string(session_invalid(id)));
            }
            // 登记待审批（needs_unlock=true）+ 广播 authz.request
            // （needsUnlock=true，D 层弹窗须同时展示主密码输入与授权栏）。
            // challenge 语义不变：一次性应答值，仅投递桌面订阅者（#78）。
            drop(vault);
            let request_id = self.open_gate_approval(
                ApprovalDraft::new(
                    req.starter.clone(),
                    req.cwd.clone(),
                    req.command.clone(),
                    req.keys.clone(),
                    lk_core::authz::ApprovalKind::Inject,
                ),
                // 锁态：规则在加密 vault 内无指纹可比（须待解锁后
                // finalize——issue #140：finalize 在临时 vault 上补裁决，
                // 失配转二次审批），审批帧不携带失配信息。
                GateEntry::unified_unlock(GateKind::Authz(PendingAuthz {
                    request: req,
                    peer: peer.clone(),
                })),
            );
            return GateBegin::Pending { request_id };
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
                    return self.open_inject_approval(id, req, peer, channel, mismatch);
                }
                // 第 2 层命中（且无绑定失配）：解密注入值 + 审计 allowed
                match self.resolve_env(ActingVault::Shared, &keys) {
                    Ok(env) => {
                        self.audit_authz(ActingVault::Shared, &req, channel, AuditResult::Allowed);
                        GateBegin::Final(rpc_string(RpcResponse::ok(
                            id,
                            serde_json::to_value(AuthzEvaluateResult {
                                allowed: true,
                                reason: None,
                                env: Some(env),
                            })
                            .unwrap_or(Value::Null),
                        )))
                    }
                    Err(e) => GateBegin::Final(rpc_string(self.err_response(id, &e))),
                }
            }
            LayerResult::Denied { reason } => {
                // 第 1 层：拒绝（不弹窗、不留内容，仅审计拒绝事件）
                self.audit_authz(ActingVault::Shared, &req, channel, AuditResult::Denied);
                GateBegin::Deny(GateDeny::Layer(reason))
            }
            LayerResult::NeedsApproval =>
            // 第 3 层：登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）；
            // 无审批界面 → fail-closed 立即拒绝（不阻塞）。
            {
                self.open_inject_approval(id, req, peer, channel, None)
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
        match crate::binding::adjudicate_binding(
            self.peer_env.as_ref(),
            peer.pid,
            &cwd,
            &req.command,
            &bound,
            &mut self.fingerprint_cache,
        ) {
            crate::binding::BindingOutcome::Allowed => FingerprintVerdict::Allowed,
            crate::binding::BindingOutcome::Mismatch(m) => {
                FingerprintVerdict::NeedsApproval(Some(m))
            }
            crate::binding::BindingOutcome::Unresolved => FingerprintVerdict::NeedsApproval(None),
        }
    }

    /// 注入审批的统一入口（解锁态 NeedsApproval 与指纹失配折叠共用）：登记
    /// 待审批 + 广播 `authz.request`（命令锁内、非阻塞）。无审批界面 → 审计
    /// 拒绝 + fail-closed 立即拒绝（与未命中同码、防探测）。解锁态常规审批
    /// 条目（无需一体化解锁，issue #150 `GateEntry::approval` 显式构造）；
    /// 解锁态 begin 已完成指纹裁决——finalize 不再重复裁决的保证随工作区
    /// 承载（issue #150），解锁态条目无工作区、finalize 走共享 vault 路径。
    fn open_inject_approval(
        &mut self,
        _id: Value,
        req: AuthzRequest,
        peer: &PeerInfo,
        channel: AuditChannel,
        fingerprint_mismatch: Option<FingerprintMismatch>,
    ) -> GateBegin {
        if !self.approval_available() {
            self.audit_authz(ActingVault::Shared, &req, channel, AuditResult::Denied);
            return GateBegin::Deny(GateDeny::NoUi);
        }
        let request_id = self.open_gate_approval(
            // #147：inject 审批不带审批子类型 / 写动作 / 导出元信息（帧不含
            // 相应字段）；指纹失配展示信息（M2.98）按携带与否补充——九字段
            // 克隆经 ApprovalDraft::new 单点构造（issue #167）。
            {
                let draft = ApprovalDraft::new(
                    req.starter.clone(),
                    req.cwd.clone(),
                    req.command.clone(),
                    req.keys.clone(),
                    lk_core::authz::ApprovalKind::Inject,
                );
                match fingerprint_mismatch {
                    Some(m) => draft.with_fingerprint_mismatch(m),
                    None => draft,
                }
            },
            GateEntry::approval(GateKind::Authz(PendingAuthz {
                request: req,
                peer: peer.clone(),
            })),
        );
        GateBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁）：收决策 → 解密 key 值 → 审计（channel=Approval）
    /// → 返回。等待期间锁定 → `session.invalid`（无法解密/审计）。
    ///
    /// **锁定态一体化（#67）**：统一注册表条目 `needs_unlock` 时，`Allowed`
    /// 决策使用审批回传时已临时解锁的 vault（条目内**审批工作区**，issue
    /// #150）：在临时 vault 上跑完整三层（第 1/2 层锁态无法预载——规则在
    /// 加密库内）+ 解析 env + 审计（用临时 vault 的 K_audit）；工作区随条目
    /// 消费即毁，不变量由构造与生命周期承载（见 gate_kit.rs
    /// `ApprovalWorkspace` 类型文档——不签令牌 / 不置共享 vault / 单次即毁）。
    ///
    /// **锁定态补指纹裁决（issue #140，M2.8 × M2.98）**：临时 vault 上规则
    /// 已可读、对端进程在审批等待期间仍存活（env 可重读）——begin 时无法
    /// 执行的指纹判定在 finalize 补上：命中 → 静默放行；失配/不可解析 →
    /// 视同未命中 → **转二次审批**（[`DeferredOutcome::RePended`]，needsUnlock
    /// 帧携带 `fingerprintMismatch` 明示「指纹不符」，identity-binding §7）；
    /// 单发状态随工作区移入二次审批条目，防裁决死循环由结构承载（issue
    /// #150）。
    pub(crate) fn authz_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> DeferredOutcome {
        // finalize = 审批注册表唯一消费移除点（拍板 #28 候选 2 三拍之三）
        let removed = self.shared.approvals.remove(&request_id);
        // 条目已被消费（极端竞态）或门不符 → 保守拒绝（决策结局）
        let (pending, workspace, needs_unlock) = match removed {
            Some(ApprovalEntry {
                needs_unlock,
                workspace,
                kind: GateKind::Authz(pending),
                ..
            }) => (pending, workspace, needs_unlock),
            _ => return DeferredOutcome::Denied(GateDeny::Rejected),
        };
        if needs_unlock {
            return self.authz_finalize_unlock(id, pending, workspace, decision);
        }
        match decision {
            ApprovalDecision::Allowed => {
                match self.resolve_env(ActingVault::Shared, &pending.request.keys) {
                    Ok(env) => {
                        self.audit_authz(
                            ActingVault::Shared,
                            &pending.request,
                            AuditChannel::Approval,
                            AuditResult::Allowed,
                        );
                        DeferredOutcome::Executed(rpc_string(RpcResponse::ok(
                            id,
                            serde_json::to_value(AuthzEvaluateResult {
                                allowed: true,
                                reason: None,
                                env: Some(env),
                            })
                            .unwrap_or(Value::Null),
                        )))
                    }
                    Err(_) => {
                        // 等待期间锁定/密钥不可用 → 执行失败（非 Denied 决策，
                        // issue #167 分层）：统一 session.invalid
                        DeferredOutcome::SessionInvalid
                    }
                }
            }
            ApprovalDecision::Denied => {
                self.audit_authz(
                    ActingVault::Shared,
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                DeferredOutcome::Denied(GateDeny::Rejected)
            }
            ApprovalDecision::Timeout => {
                self.audit_authz(
                    ActingVault::Shared,
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Timeout,
                );
                DeferredOutcome::Denied(GateDeny::Timeout)
            }
        }
    }

    /// 锁定态一体化 finalize（#67，见 [`Self::authz_finalize`]）。审批工作区
    /// 由 `approval_result`（正确主密码）填充（统一注册表条目内一等对象，
    /// issue #150），缺失（异常路径）→ 保守拒绝；工作区 vault 只借用——
    /// 单次执行后随工作区（条目）整体销毁。
    fn authz_finalize_unlock(
        &mut self,
        id: Value,
        pending: PendingAuthz,
        workspace: Option<ApprovalWorkspace>,
        decision: ApprovalDecision,
    ) -> DeferredOutcome {
        let PendingAuthz { request: req, peer } = pending;
        let req = &req;
        match decision {
            ApprovalDecision::Allowed => {
                // 工作区由 approval_result 以正确主密码解锁后存入；
                // 缺失（异常路径）→ 保守拒绝（执行层，issue #167 分层）
                let Some(workspace) = workspace else {
                    return DeferredOutcome::ExecutionDenied(GateDeny::Rejected);
                };
                // 锁定态补指纹裁决（issue #140，identity-binding.md §2 目标 2/
                // §3/§7）：临时解锁后规则在临时 vault 内、对端 env 可读——
                // 失配/不可解析 → 视同未命中 → 转二次审批（弹窗明示「指纹
                // 不符」）；命中/未绑定 → 沿既有语义继续。单发状态随工作区
                // 走（issue #150）：已裁决的工作区不再裁决——弹窗批准即
                // 「本次允许」。
                if !workspace.fingerprint_adjudicated() {
                    let verdict = self.fingerprint_adjudicate(req, &peer, workspace.vault());
                    if let FingerprintVerdict::NeedsApproval(mismatch) = verdict {
                        return self.authz_finalize_reopen(id, req, peer, workspace, mismatch);
                    }
                }
                // 完整三层裁决（锁态 begin 无法预载规则/解析 key；解锁后
                // 一次性在临时 vault 上跑：第 1/2 层短路、未命中则第 3 层
                // 已由弹窗批准视同通过）
                let vault = workspace.vault();
                let secrets = vault.secret_values().unwrap_or_default();
                let layer = self
                    .gate
                    .evaluate_layers(req, &VaultRuleView { vault, secrets });
                match layer {
                    LayerResult::Allowed { keys } => {
                        match self.resolve_env(ActingVault::Temporary(vault), &keys) {
                            Ok(env) => {
                                self.audit_authz(
                                    ActingVault::Temporary(vault),
                                    req,
                                    AuditChannel::Approval,
                                    AuditResult::Allowed,
                                );
                                DeferredOutcome::Executed(rpc_string(RpcResponse::ok(
                                    id,
                                    serde_json::to_value(AuthzEvaluateResult {
                                        allowed: true,
                                        reason: None,
                                        env: Some(env),
                                    })
                                    .unwrap_or(Value::Null),
                                )))
                            }
                            Err(_) => DeferredOutcome::SessionInvalid,
                        }
                    }
                    LayerResult::Denied { reason } => {
                        self.audit_authz(
                            ActingVault::Temporary(vault),
                            req,
                            AuditChannel::Approval,
                            AuditResult::Denied,
                        );
                        DeferredOutcome::Denied(GateDeny::Layer(reason))
                    }
                    // 未命中规则：第 3 层弹窗已批准（allowed 决策即批准）
                    LayerResult::NeedsApproval => {
                        match self.resolve_env(ActingVault::Temporary(vault), &req.keys) {
                            Ok(env) => {
                                self.audit_authz(
                                    ActingVault::Temporary(vault),
                                    req,
                                    AuditChannel::Approval,
                                    AuditResult::Allowed,
                                );
                                DeferredOutcome::Executed(rpc_string(RpcResponse::ok(
                                    id,
                                    serde_json::to_value(AuthzEvaluateResult {
                                        allowed: true,
                                        reason: None,
                                        env: Some(env),
                                    })
                                    .unwrap_or(Value::Null),
                                )))
                            }
                            Err(_) => DeferredOutcome::SessionInvalid,
                        }
                    }
                }
                // 工作区随本函数结束 drop——临时解锁态销毁（不变量由构造与
                // 生命周期承载，见 gate_kit.rs ApprovalWorkspace 类型文档）
            }
            // 拒绝/超时：未解锁（无工作区）→ 无 K_audit 可签名，审计
            // 不可写（与 v0 锁态拒绝同口径——fail-closed 不留审计内容）
            ApprovalDecision::Denied => DeferredOutcome::Denied(GateDeny::Rejected),
            ApprovalDecision::Timeout => DeferredOutcome::Denied(GateDeny::Timeout),
        }
    }

    /// 锁定态一体化 finalize 的指纹失配转**二次审批**（issue #140）：审批
    /// 工作区随新待审条目存留（issue #150 条目内一等对象；不签令牌 /
    /// 不置共享 vault 的不变量由工作区类型承载），帧 needsUnlock=true——
    /// 锁态前端门控只放行一体化帧，弹窗渲染失配主题「程序指纹与规则不符
    /// （可能已更新）」+ 主密码栏（identity-binding §7；「以新指纹重新授权」
    /// 按钮为失配帧解锁态形态预留，锁态二次批准 = 本次允许语义）。桌面审批
    /// 界面不在场（审批期间断开）→ 用临时 vault 的 K_audit 审计拒绝 +
    /// fail-closed no_ui（与解锁态 headless 失配同码、防探测）。
    fn authz_finalize_reopen(
        &mut self,
        _id: Value,
        req: &AuthzRequest,
        peer: PeerInfo,
        mut workspace: ApprovalWorkspace,
        mismatch: Option<FingerprintMismatch>,
    ) -> DeferredOutcome {
        if !self.approval_available() {
            // 二次审批界面离场（审批期间断开）→ 用临时 vault 的 K_audit 审计
            // 拒绝 + fail-closed no_ui（与解锁态 headless 失配同码、防探测）。
            // 执行层保守拒绝（issue #167 分层：决策已 Allowed、转二次审批的
            // 执行材料离场，非 Denied 决策），字节走本门拒绝尾（ok{no_ui}）。
            self.audit_authz(
                ActingVault::Temporary(workspace.vault()),
                req,
                AuditChannel::Approval,
                AuditResult::Denied,
            );
            return DeferredOutcome::ExecutionDenied(GateDeny::NoUi);
        }
        // 二次审批不再重复指纹裁决（单发状态已随工作区标记，issue #150；
        // 防裁决 → 审批 → 裁决死循环由结构承载——二次弹窗批准即本次允许，
        // identity-binding §7 失配批准语义）
        workspace.mark_fingerprint_adjudicated();
        let mut entry = GateEntry::unified_unlock(GateKind::Authz(PendingAuthz {
            request: req.clone(),
            peer,
        }));
        // 工作区（含临时解锁材料）随新条目存留（finalize 消费即毁）
        entry.workspace = Some(workspace);
        let request_id = self.open_gate_approval(
            {
                // inject 审批只携带指纹失配展示信息（M2.98）；其余门事实
                // 字段恒 None——九字段克隆单点构造（issue #167）。
                let draft = ApprovalDraft::new(
                    req.starter.clone(),
                    req.cwd.clone(),
                    req.command.clone(),
                    req.keys.clone(),
                    lk_core::authz::ApprovalKind::Inject,
                );
                match mismatch {
                    Some(m) => draft.with_fingerprint_mismatch(m),
                    None => draft,
                }
            },
            entry,
        );
        DeferredOutcome::RePended { request_id }
    }

    /// 解析注入 env（「本次执行所用 vault」；key 名 → 值；仅被授权 key；
    /// 单次扫描）。Shared 已锁定 → `session.invalid`（既有口径）；
    /// Temporary = 锁定态一体化临时 vault（审批工作区借用，issue #150）。
    pub(crate) fn resolve_env(
        &self,
        acting: ActingVault<'_>,
        keys: &[String],
    ) -> Result<std::collections::BTreeMap<String, String>> {
        self.with_acting_vault(acting, |v| {
            let v = v.ok_or(Error::SessionInvalid)?;
            let all = v.secret_values()?;
            let mut env = std::collections::BTreeMap::new();
            for k in keys {
                if let Some(value) = all.get(k) {
                    env.insert(k.clone(), value.clone());
                }
            }
            Ok(env)
        })
    }

    /// 授权路径审计（authz.rs 门事件摘要）：command 脱敏为
    /// `lk inject <sha256:8>`（audit.md §2），target=命令首词；事件字段外
    /// 的签名统一走 [`Daemon::audit_gate`]——按「本次执行所用 vault」
    /// （Shared = 共享 vault；Temporary = 锁定态一体化的临时 vault，#67）。
    fn audit_authz(
        &self,
        acting: ActingVault<'_>,
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
        self.audit_gate(
            acting,
            &req.starter,
            &target,
            &format!("lk inject <{short}>"),
            channel,
            result,
        );
    }
}

// -------------------------------------------------------------------------
// 门声明（issue #167：静态声明取代 DeferredFlow trait 空壳；注册于
// router.rs 流程注册表）
// -------------------------------------------------------------------------

/// 注入门拒绝响应渲染器（issue #167）：(门 × 锁态/会话态 × reason) → 字节
/// 的**唯一决定点**。inject 的 spec 钉死形态 = `ok{allowed:false,reason}`
/// （authorization-gate §5；与其余三门 `authz.denied`(-32017) 字节不同，
/// 不得跨门压平）。锁态 headless 的 `session.invalid` 是会话前置失败
/// （编排器预检 / begin 锁态分支直返 Final，分层见 [`GateBegin`] 类型
/// 文档），不经本渲染器——渲染器拿 daemon 上下文是为未来「拒绝码随锁态
/// 变化」的门保留决定面，也是防把渲染误写成全局「决策 → 字节」纯函数的
/// 结构钩子（golden 表钉住全部字节，tests/gate_golden.rs）。
fn render_inject_deny(_daemon: &Daemon, id: Value, deny: GateDeny) -> String {
    rpc_string(RpcResponse::ok(
        id,
        serde_json::to_value(AuthzEvaluateResult {
            allowed: false,
            reason: Some(deny.as_str().to_string()),
            env: None,
        })
        .unwrap_or(Value::Null),
    ))
}

/// 注入门静态声明：**可 RePended**——锁态一体化 finalize 补指纹裁决失配
/// 转二次审批（issue #140），RePended 循环内建于编排器（注入裁决不再是
/// 编排特例）；支持锁态一体化解锁（#67）。
pub(crate) static AUTHZ_GATE: crate::router::GateDecl = crate::router::GateDecl {
    name: "authz.evaluate",
    rependable: true,
    unlock_supported: true,
    precheck: Daemon::authz_evaluate_precheck,
    begin: Daemon::authz_begin,
    finalize: Daemon::authz_finalize,
    render_deny: render_inject_deny,
};
