//! 写入授权门（M2.97，补充拍板 #24；规格唯一出处 write-gate.md）：
//! `item.put` / `item.delete` 的三阶段两段（阶段① begin / 阶段③ finalize）、
//! 执行与审计。最佳模板 = 规则门（daemon/rules.rs）+ 值披露
//! （daemon/disclosure.rs）。
//!
//! 判定矩阵（spec §3）：desktop 内嵌直调受信豁免直执行；socket 通道
//! `item.put` 写规则命中（§4 双向名约束，`lk_core::authz::write_rule_matches`）
//! → 静默放行；未命中 → 桌面弹窗（无 UI fail-closed）；**`item.delete`
//! 跳过规则匹配恒弹窗**（无用户级恢复路径，对齐 export 恒弹窗先例）。
//! 锁定态 → `session.invalid` 先行不弹窗（写门不弹解锁窗，§5.3——一体化
//! 留档不做，§12）。拒绝统一 `authz.denied`（-32017，协议零新增，§5.5）。
//!
//! action 权威派生（§5.2 拍板）：`ItemPutParams.id` None = create /
//! Some = update，不信客户端自报；daemon 内部拆 `item_create_exec` /
//! `item_update_exec`（daemon/items.rs），`item.delete` 维持独立方法。
//!
//! 审计（§8）：command 按 action 派生 `item.create/update/delete <name>`，
//! target=条目名，值不明文；unknown starter / no_ui / denied / timeout
//! 失败路径均落审计（K_audit 可用时；timeout 统一记 denied，对齐值披露
//! §8 防探测口径）。

use super::*;

/// 阶段① 结果：最终响应（desktop 豁免 / 写规则命中 / fail-closed 拒绝 /
/// 参数错误）或待审批（等待移出命令锁，G1）。
pub(crate) enum WriteBegin {
    Final(String),
    Pending { request_id: uuid::Uuid },
}

/// 写门第 3 层待办操作（begin 期已解析；finalize 重执行）。
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingWriteOp {
    /// `item.put` create（id=None，§5.2 权威派生）。
    Create,
    /// `item.put` update（id=Some；finalize 锁内执行，CAS 冲突照旧直返）。
    Update(uuid::Uuid),
    /// `item.delete`（恒弹窗路径；finalize 锁内按**未删除**口径重验）。
    Delete(uuid::Uuid),
}

/// 写门待办（等待期间由发起连接线程持有，锁外等待）。
pub(crate) struct PendingWrite {
    op: PendingWriteOp,
    /// `item.put` create/update 的草稿（begin 期已解析）。
    draft: Option<ItemDraft>,
    /// update 的 CAS 基准（协议字段原样透传执行层）。
    expected_revision: Option<String>,
    /// 审计 command 摘要（按 action 派生：`item.create/update/delete <name>`，
    /// §8）。
    command_summary: String,
    /// 审计 target（条目名；create/update=草稿名，delete=存储名）。
    target: String,
    /// 真实启动者（#66 进程链回溯；finalize 审计 starter 用）。
    starter: String,
}

/// 草稿条目名（`ItemDraft` 四类型均携带 name；write-gate.md §4）。
fn draft_name(draft: &ItemDraft) -> &str {
    match draft {
        ItemDraft::Login { name, .. }
        | ItemDraft::Note { name, .. }
        | ItemDraft::Secret { name, .. }
        | ItemDraft::File { name, .. } => name,
    }
}

impl Daemon {
    /// 写门预检：锁定 → `session.invalid` 先行（写门不弹解锁窗，规则在
    /// 加密 vault 内；未初始化库同口径）；解锁态 = 令牌有效（与
    /// `rule_precheck` 同型）。
    pub(crate) fn write_precheck(&self, token: Option<&[u8]>) -> bool {
        self.vault_peek() && self.sessions.validate(token.unwrap_or(&[]))
    }

    /// 阶段①（命令锁内，非阻塞；write-gate.md §5.3）：
    ///
    /// 1. 参数解析（无效参数原错误直返，与既有 Inline 语义一致）；
    /// 2. 解析目标条目名（update/delete 按 id；不存在 → `item.not_found`
    ///    现状语义）+ action 权威派生（id None=create / Some=update）；
    /// 3. desktop 直调受信豁免 → 直接执行（不登记审批）；
    /// 4. socket：真实 starter + cwd（#66 归因链路）；未知 → fail-closed
    ///    拒绝不弹窗；
    /// 5. 写规则匹配（create/update；**delete 跳过**恒弹窗）→ 命中静默放行；
    /// 6. 未命中：无审批界面 → 立即拒绝；否则登记 `PendingApprovals`
    ///    （challenge 防伪 #78）+ 广播 `authz.request`。
    pub(crate) fn write_begin(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        peer: &PeerInfo,
    ) -> WriteBegin {
        // 1) 参数解析 + action 权威派生（§5.2）
        let parsed = match self.write_parse(method, &params) {
            Ok(p) => p,
            Err(resp) => return WriteBegin::Final(rpc_string(*resp)),
        };
        // 2) 解析目标条目名（update/delete 按 id；审计 target 与弹窗 keys 用）
        let stored_name = match parsed.op {
            PendingWriteOp::Create => None,
            PendingWriteOp::Update(item_id) | PendingWriteOp::Delete(item_id) => {
                let shared = Arc::clone(&self.shared);
                let guard = shared.vault.read().unwrap();
                let me = guard.as_ref().unwrap();
                match me.get(item_id) {
                    Ok(item) => Some(item.name().to_string()),
                    Err(e) => return WriteBegin::Final(rpc_string(self.err_response(id, &e))),
                }
            }
        };
        let target = match parsed.op {
            PendingWriteOp::Create | PendingWriteOp::Update(_) => parsed
                .draft
                .as_ref()
                .map(draft_name)
                .unwrap_or_default()
                .to_string(),
            PendingWriteOp::Delete(_) => stored_name.clone().unwrap_or_default(),
        };
        // 3) GUI desktop 直调受信豁免（人在 GUI 前）：直接执行 + 审计
        //    （channel=desktop，spec §3 第 1 行）
        if peer.origin == PeerOrigin::Desktop {
            let resp = self.write_exec(
                id,
                &parsed.op,
                parsed.draft,
                parsed.expected_revision,
                "desktop",
                AuditChannel::Desktop,
            );
            return WriteBegin::Final(rpc_string(resp));
        }
        // 4) socket 通道：真实 starter + cwd（#66 归因链路复用；客户端自报
        //    字段不信任）；未知 → 第 1 层 fail-closed 拒绝（不弹窗、不留内容）
        let starter = derive_starter(peer);
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let channel = peer_channel(peer);
        let command_summary = write_command_summary(&parsed.op, &target);
        if starter == UNKNOWN_STARTER || cwd.is_empty() {
            self.audit_write_gate(
                &command_summary,
                &target,
                &starter,
                channel,
                AuditResult::Denied,
            );
            return WriteBegin::Final(rpc_string(super::disclosure::authz_denied(id)));
        }
        // 5) 写规则匹配（§4 双向名约束；delete 跳过——恒弹窗）
        if let Some(action) = write_action(&parsed.op) {
            let hit = {
                let shared = Arc::clone(&self.shared);
                let guard = shared.vault.read().unwrap();
                let me = guard.as_ref().unwrap();
                me.list_rules().unwrap_or_default().iter().any(|r| {
                    lk_core::authz::write_rule_matches(
                        r,
                        &cwd,
                        action,
                        stored_name.as_deref(),
                        &target,
                    )
                })
            };
            if hit {
                let resp = self.write_exec(
                    id,
                    &parsed.op,
                    parsed.draft,
                    parsed.expected_revision,
                    &starter,
                    channel,
                );
                return WriteBegin::Final(rpc_string(resp));
            }
        }
        // 6) 无审批界面（headless）→ fail-closed 立即拒绝（不登记、不阻塞；
        //    E2E 自动批准不扩到写门——弹窗路径由集成测试覆盖，拍板 #24）
        if !self.gate.approval().available() {
            self.audit_write_gate(
                &command_summary,
                &target,
                &starter,
                channel,
                AuditResult::Denied,
            );
            return WriteBegin::Final(rpc_string(super::disclosure::authz_denied(id)));
        }
        // 7) 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）：kind=
        //    write、command=`item.put/delete <name>`（展示用）、keys=单元素
        //    [目标条目名]、project_dir=cwd、needs_unlock=false、export_meta
        //    恒 None（§5.3 步骤 7 / §6）。challenge 语义同 inject——仅投递
        //    桌面订阅者，回传必须原样带回（#78）。
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let display_command = format!(
            "{} {}",
            match parsed.op {
                PendingWriteOp::Delete(_) => M_ITEM_DELETE,
                _ => M_ITEM_PUT,
            },
            target
        );
        let areq = ApprovalRequest {
            request_id,
            starter: starter.clone(),
            project_dir: cwd,
            command: display_command,
            keys: vec![target.clone()],
            challenge,
            needs_unlock: false,
            kind: lk_core::authz::ApprovalKind::Write,
            export_meta: None,
            fingerprint_mismatch: None,
        };
        self.gate.approval().open(&areq, expires_at);
        self.pending_write.lock().unwrap().insert(
            request_id,
            PendingWrite {
                op: parsed.op,
                draft: parsed.draft,
                expected_revision: parsed.expected_revision,
                command_summary,
                target,
                starter,
            },
        );
        WriteBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁；write-gate.md §5.4）：Allowed → **锁内 TOCTOU
    /// 重校验**（等待窗内可能被并发审批落盘 / 同步轮次应用远端变更 / 锁定）
    /// → 执行 + 审计（channel=approval）；deny / timeout / 重验失效 →
    /// `authz.denied` + 审计。
    pub(crate) fn write_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let pending = self.pending_write.lock().unwrap().remove(&request_id);
        let Some(p) = pending else {
            // 条目已被消费（极端竞态）→ 保守拒绝
            return rpc_string(super::disclosure::authz_denied(id));
        };
        match decision {
            ApprovalDecision::Allowed => {
                // TOCTOU 重校验①：vault 解锁态（等待期锁定 → K_audit 已擦除，
                // 无法签名审计，与披露/规则门 finalize 同口径保守 session.invalid）
                if !self.vault_peek() {
                    return rpc_string(session_invalid(id));
                }
                // TOCTOU 重校验②：delete 目标仍存在（按**未删除**口径——
                // `read_item_file` 含墓碑、幂等 delete 静默成功，不能用作
                // 重验；与规则门 remove 的 `get_rule` 教训同款）
                if let PendingWriteOp::Delete(item_id) = p.op {
                    let still_present = {
                        let shared = Arc::clone(&self.shared);
                        let guard = shared.vault.read().unwrap();
                        guard
                            .as_ref()
                            .map(|v| v.get(item_id).map(|i| !i.deleted()).unwrap_or(false))
                            .unwrap_or(false)
                    };
                    if !still_present {
                        self.audit_write_gate(
                            &p.command_summary,
                            &p.target,
                            &p.starter,
                            AuditChannel::Approval,
                            AuditResult::Denied,
                        );
                        return rpc_string(super::disclosure::authz_denied(id));
                    }
                }
                // 执行 + 审计（弹窗批准 → channel=approval）
                let resp = self.write_exec(
                    id,
                    &p.op,
                    p.draft,
                    p.expected_revision,
                    &p.starter,
                    AuditChannel::Approval,
                );
                rpc_string(resp)
            }
            ApprovalDecision::Denied | ApprovalDecision::Timeout => {
                // 拒绝/超时统一 denied（§8：不区分原因防探测，与值披露同口径）
                self.audit_write_gate(
                    &p.command_summary,
                    &p.target,
                    &p.starter,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                rpc_string(super::disclosure::authz_denied(id))
            }
        }
    }

    /// 参数解析 + action 权威派生（`ItemPutParams.id` None=create /
    /// Some=update，§5.2——不信任客户端自报；协议结构零变更）。
    fn write_parse(
        &self,
        method: &str,
        params: &Value,
    ) -> std::result::Result<ParsedWrite, Box<RpcResponse>> {
        match method {
            M_ITEM_PUT => {
                let p: ItemPutParams = match serde_json::from_value(params.clone()) {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(Box::new(RpcResponse::err(
                            Value::Null,
                            ERR_INVALID_PARAMS,
                            "invalid params",
                            None,
                        )))
                    }
                };
                let (op, draft, expected_revision) = match p.id {
                    None => (PendingWriteOp::Create, Some(p.item), None),
                    Some(item_id) => (
                        PendingWriteOp::Update(item_id),
                        Some(p.item),
                        p.expected_revision,
                    ),
                };
                Ok(ParsedWrite {
                    op,
                    draft,
                    expected_revision,
                })
            }
            M_ITEM_DELETE => {
                let p: ItemDeleteParams = match serde_json::from_value(params.clone()) {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(Box::new(RpcResponse::err(
                            Value::Null,
                            ERR_INVALID_PARAMS,
                            "invalid params",
                            None,
                        )))
                    }
                };
                Ok(ParsedWrite {
                    op: PendingWriteOp::Delete(p.id),
                    draft: None,
                    expected_revision: None,
                })
            }
            _ => Err(Box::new(RpcResponse::err(
                Value::Null,
                ERR_METHOD_NOT_FOUND,
                MSG_METHOD_NOT_FOUND,
                None,
            ))),
        }
    }

    /// 落盘 + 审计 + 响应（desktop 豁免 / 写规则命中 / finalize 批准共用）。
    /// action → 执行核心的分派（§5.2 内部拆分：`item_create_exec` /
    /// `item_update_exec` / `item_delete_exec`，协议不拆）。
    fn write_exec(
        &mut self,
        id: Value,
        op: &PendingWriteOp,
        draft: Option<ItemDraft>,
        expected_revision: Option<String>,
        starter: &str,
        channel: AuditChannel,
    ) -> RpcResponse {
        match *op {
            PendingWriteOp::Create => {
                let draft = draft.expect("create 形态必须携带草稿（begin 期已解析）");
                self.item_create_exec(id, draft, starter, channel)
            }
            PendingWriteOp::Update(item_id) => {
                let draft = draft.expect("update 形态必须携带草稿（begin 期已解析）");
                self.item_update_exec(id, item_id, draft, expected_revision, starter, channel)
            }
            PendingWriteOp::Delete(item_id) => self.item_delete_exec(id, item_id, starter, channel),
        }
    }

    /// 写门拒绝/超时审计（失败路径全落审计，§8；补充拍板 #22 规则门同款）：
    /// command 按 action 派生、target=条目名、starter/channel=真实归因。
    /// K_audit 签名；已锁定（K_audit 擦除）→ 跳过（与授权路径审计同口径）。
    fn audit_write_gate(
        &self,
        command: &str,
        target: &str,
        starter: &str,
        channel: AuditChannel,
        result: AuditResult,
    ) {
        let vault = self.shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return;
        };
        let _ = self.audit.append(
            v.keys(),
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

/// begin 期解析产物（op + 草稿 + CAS 基准）。
struct ParsedWrite {
    op: PendingWriteOp,
    draft: Option<ItemDraft>,
    expected_revision: Option<String>,
}

/// 审计 command 按 action 派生（§8：`item.create/update/delete <name>`）。
fn write_command_summary(op: &PendingWriteOp, target: &str) -> String {
    let verb = match op {
        PendingWriteOp::Create => "item.create",
        PendingWriteOp::Update(_) => "item.update",
        PendingWriteOp::Delete(_) => "item.delete",
    };
    format!("{verb} {target}")
}

/// 规则匹配的 action（delete 不参与匹配——恒弹窗，§3/§4：`WriteAction`
/// 无 Delete 变体）。
fn write_action(op: &PendingWriteOp) -> Option<lk_core::authz::WriteAction> {
    match op {
        PendingWriteOp::Create => Some(lk_core::authz::WriteAction::Create),
        PendingWriteOp::Update(_) => Some(lk_core::authz::WriteAction::Update),
        PendingWriteOp::Delete(_) => None,
    }
}
