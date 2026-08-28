//! 值披露裁决（M2.9，value-disclosure.md）：`item.get` / `item.export` 的
//! 三阶段两段（阶段① begin / 阶段③ finalize）+ 披露执行 + 审计。
//!
//! 判定矩阵（spec §3）：desktop 内嵌直调受信豁免直返；socket 通道
//! `item.get` 读规则命中 → 静默放行，未命中 → 弹窗（无 UI fail-closed）；
//! `item.export` 恒弹窗（任何规则不豁免）。拒绝统一 `authz.denied`
//! （-32017，不区分原因防探测；spec §5.4 实现注记——-32015 被
//! `ERR_BRIDGE_*` 占用）。审计 spec §8：command=`item.get` /
//! `item.export`，target=条目名，starter/channel=真实归因。

use super::*;

/// 阶段① 结果：最终响应（desktop 豁免 / 规则命中 / fail-closed 拒绝）或
/// 待审批（等待移出命令锁，G1）。
pub(crate) enum DisclosureBegin {
    Final(String),
    Pending { request_id: uuid::Uuid },
}

/// 值披露第 3 层的待办（等待期间由发起连接线程持有，锁外等待）。
pub(crate) struct PendingDisclosure {
    /// `item.get` | `item.export`（决定 finalize 披露形态）。
    pub method: String,
    pub item_id: uuid::Uuid,
    /// begin 期按 id 解析的条目名（finalize 审计 target 用）。
    pub item_name: String,
    /// 真实启动者（#66 进程链回溯；finalize 审计 starter 用）。
    pub starter: String,
}

impl Daemon {
    /// 值披露预检（spec §3：锁定 → `session.invalid`，读通道不做 #67 式
    /// 解锁一体化）：解锁态 + 令牌有效。
    pub(crate) fn disclosure_precheck(&self, token: Option<&[u8]>) -> bool {
        self.vault_peek() && self.sessions.validate(token.unwrap_or(&[]))
    }

    /// 阶段①（命令锁内，非阻塞；spec §5.2 步骤 1-7）。
    pub(crate) fn disclosure_begin(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        peer: &PeerInfo,
    ) -> DisclosureBegin {
        // 1) 参数解析（id 必填；channel 为可选审计来源标注，§8——缺省按
        //    对端来源，wsl-bridge 客户端标注优先，与 rule.* 同口径）
        let (item_id, channel_param) = match method {
            M_ITEM_GET => match serde_json::from_value::<ItemGetParams>(params) {
                Ok(p) => (p.id, p.channel),
                Err(_) => {
                    return DisclosureBegin::Final(rpc_string(RpcResponse::err(
                        id,
                        ERR_INVALID_PARAMS,
                        "invalid params",
                        None,
                    )))
                }
            },
            M_ITEM_EXPORT => match serde_json::from_value::<ItemExportParams>(params) {
                Ok(p) => (p.id, p.channel),
                Err(_) => {
                    return DisclosureBegin::Final(rpc_string(RpcResponse::err(
                        id,
                        ERR_INVALID_PARAMS,
                        "invalid params",
                        None,
                    )))
                }
            },
            _ => {
                return DisclosureBegin::Final(rpc_string(RpcResponse::err(
                    id,
                    ERR_METHOD_NOT_FOUND,
                    MSG_METHOD_NOT_FOUND,
                    None,
                )))
            }
        };
        // 2) 解析条目：id → 条目名（不存在 → `item.not_found`，现状语义）；
        //    export 顺带解析数据包元信息（弹窗展示规模用，不解密附件数据）
        let (item_name, export_meta) = {
            let shared = Arc::clone(&self.shared);
            let guard = shared.vault.read().unwrap();
            let me = guard.as_ref().unwrap();
            match me.get(item_id) {
                Ok(item) => {
                    let meta = if method == M_ITEM_EXPORT {
                        // file 条目才有数据包（附件名/mime/size）；其余类型
                        // 元信息缺省，弹窗仅展示条目名，执行时报原错误
                        match &item {
                            lk_core::model::Item::File {
                                attachment,
                                file_type,
                                size,
                                ..
                            } => Some(lk_core::authz::ExportMeta {
                                name: attachment.clone(),
                                mime: file_type.clone(),
                                size: *size,
                            }),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    (item.name().to_string(), meta)
                }
                Err(e) => return DisclosureBegin::Final(rpc_string(self.err_response(id, &e))),
            }
        };
        // 3) 通道判定：desktop 内嵌直调 → 受信豁免直返（不登记审批；
        //    GUI 读值体验零变化，spec §3 第 1 行）
        if peer.origin == PeerOrigin::Desktop {
            let resp = match method {
                M_ITEM_GET => self.item_get_exec(id, item_id, "desktop", AuditChannel::Desktop),
                _ => self.item_export_exec(id, item_id, "desktop", AuditChannel::Desktop),
            };
            return DisclosureBegin::Final(rpc_string(resp));
        }
        // 4) socket 通道：真实 starter + cwd（#66 归因链路复用；客户端自报
        //    字段不信任）；未知 → 第 1 层 fail-closed 拒绝（不弹窗、不留内容）
        let starter = derive_starter(peer);
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let channel = client_channel(channel_param.as_deref(), peer_channel(peer));
        if starter == UNKNOWN_STARTER || cwd.is_empty() {
            self.audit_disclosure(method, &item_name, &starter, channel, AuditResult::Denied);
            return DisclosureBegin::Final(rpc_string(authz_denied(id)));
        }
        // 5) item.get：读规则匹配（spec §4）→ 命中静默放行 + 审计 allowed
        if method == M_ITEM_GET {
            let hit = {
                let shared = Arc::clone(&self.shared);
                let guard = shared.vault.read().unwrap();
                let me = guard.as_ref().unwrap();
                me.list_rules()
                    .unwrap_or_default()
                    .iter()
                    .any(|r| lk_core::authz::read_rule_matches(r, &cwd, &item_name))
            };
            if hit {
                let resp = self.item_get_exec(id, item_id, &starter, channel);
                return DisclosureBegin::Final(rpc_string(resp));
            }
        }
        // 6) get 未命中 / export 恒弹窗：无审批界面 → fail-closed 立即拒绝
        if !self.gate.approval().available() {
            self.audit_disclosure(method, &item_name, &starter, channel, AuditResult::Denied);
            return DisclosureBegin::Final(rpc_string(authz_denied(id)));
        }
        // 7) 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞；challenge
        //    语义同 inject——仅投递桌面订阅者，回传必须原样带回，#78）
        let kind = if method == M_ITEM_GET {
            lk_core::authz::ApprovalKind::Read
        } else {
            lk_core::authz::ApprovalKind::Export
        };
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let areq = ApprovalRequest {
            request_id,
            starter: starter.clone(),
            project_dir: cwd,
            command: method.to_string(),
            keys: vec![item_name.clone()],
            challenge: challenge.clone(),
            needs_unlock: false,
            kind,
            export_meta: if method == M_ITEM_EXPORT {
                export_meta
            } else {
                None
            },
        };
        self.gate.approval().open(&areq, expires_at);
        self.pending_disclosure.lock().unwrap().insert(
            request_id,
            PendingDisclosure {
                method: method.to_string(),
                item_id,
                item_name,
                starter,
            },
        );
        DisclosureBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁；spec §5.3）：Allowed → 披露值/数据包 + 审计
    /// allowed（channel=approval 与 inject 同口径）；deny / timeout / 条目
    /// 被消费（极端竞态）→ `authz.denied` + 审计。等待期间锁定 →
    /// `session.invalid`（exec 内 vault 为空时保守失败，无法签名审计）。
    pub(crate) fn disclosure_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let pending = self.pending_disclosure.lock().unwrap().remove(&request_id);
        let Some(p) = pending else {
            // 条目已被消费（极端竞态）→ 保守拒绝
            return rpc_string(authz_denied(id));
        };
        match decision {
            ApprovalDecision::Allowed => {
                // 等待期间锁定（手动/自动/锁屏/恢复）：vault 与 K_audit 已
                // 擦除，无法披露也无法签名审计 → 保守 `session.invalid`
                // （与 authz_finalize resolve_env 失败同口径；exec 不再 unwrap）
                if !self.vault_peek() {
                    return rpc_string(session_invalid(id));
                }
                let resp = match p.method.as_str() {
                    M_ITEM_GET => {
                        self.item_get_exec(id, p.item_id, &p.starter, AuditChannel::Approval)
                    }
                    _ => self.item_export_exec(id, p.item_id, &p.starter, AuditChannel::Approval),
                };
                rpc_string(resp)
            }
            ApprovalDecision::Denied | ApprovalDecision::Timeout => {
                // 拒绝/超时统一 denied（spec §8：不区分原因，防探测）
                self.audit_disclosure(
                    &p.method,
                    &p.item_name,
                    &p.starter,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                rpc_string(authz_denied(id))
            }
        }
    }

    /// 值披露审计（spec §8）：command=`item.get`/`item.export`、
    /// target=条目名、starter/channel=真实归因。K_audit 签名；已锁定
    /// （K_audit 擦除）→ 跳过（与授权路径审计同口径）。
    fn audit_disclosure(
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

/// 统一「值披露拒绝」错误响应（`authz.denied` / -32015）。
pub(crate) fn authz_denied(id: Value) -> RpcResponse {
    RpcResponse::err(id, ERR_AUTHZ_DENIED, MSG_AUTHZ_DENIED, None)
}
