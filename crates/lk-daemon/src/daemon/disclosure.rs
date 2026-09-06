//! 值披露裁决（M2.9，value-disclosure.md）：`item.get` / `item.export` 的
//! 三阶段两段（阶段① begin / 阶段③ finalize）+ 披露执行 + 审计。
//!
//! 判定矩阵（spec §3）：desktop 内嵌直调受信豁免直返；socket 通道
//! `item.get` 读规则命中 → 静默放行，未命中 → 弹窗（无 UI fail-closed）；
//! `item.export` 恒弹窗（任何规则不豁免）。拒绝统一 `authz.denied`
//! （-32017，不区分原因防探测；spec §5.4 实现注记——-32015 被
//! `ERR_BRIDGE_*` 占用）。审计 spec §8：command=`item.get` /
//! `item.export`，target=条目名，starter/channel=真实归因。
//!
//! 锁定态一体化（补充拍板 #23，issue #105）：锁定态 + 桌面 UI 在场时的
//! `item.get` / `item.export` 走与 #67 inject 同款的一体化弹窗——登记
//! `Pending{needs_unlock:true}` 并广播 `authz.request(needsUnlock=true)`，
//! `approval.result`（allowed + masterPassword）先做临时解锁，finalize 在
//! **临时 vault** 上执行披露（单次即毁，不签发令牌 / 不写 session.token /
//! 不置 shared.vault，#65 边界）；未初始化库 / headless 仍 fail-closed。
//!
//! 五件套下沉（issue #148）：begin 结果（GateBegin）/ 统一注册表（GateEntry，
//! needs_unlock 与临时 vault 条目级承载）/ 审批单点铸造 / 审计辅助
//! （audit_gate）出自 daemon/gate_kit.rs。

use super::*;

/// 披露审批类型（读/导出共用；加性协议值，value-disclosure.md §6）。
fn disclosure_kind(method: &str) -> lk_core::authz::ApprovalKind {
    if method == M_ITEM_GET {
        lk_core::authz::ApprovalKind::Read
    } else {
        lk_core::authz::ApprovalKind::Export
    }
}

/// 值披露第 3 层的待办（等待期间由发起连接线程持有，锁外等待）。
/// needs_unlock / 临时 vault 提升到统一注册表条目级
/// （[`super::gate_kit::GateEntry`]，issue #148），门负载只携带披露特有字段。
pub(crate) struct PendingDisclosure {
    /// `item.get` | `item.export`（决定 finalize 披露形态）。
    pub method: String,
    pub item_id: uuid::Uuid,
    /// begin 期按 id 解析的条目名（finalize 审计 target 用）。锁定态一体化
    /// （补充拍板 #23）时 begin 无法解析（vault 加密），为 None——finalize
    /// 在临时 vault 上解析。
    pub item_name: Option<String>,
    /// 真实启动者（#66 进程链回溯；finalize 审计 starter 用）。
    pub starter: String,
}

impl Daemon {
    /// 值披露预检：解锁态 = 令牌有效；
    /// **锁态（补充拍板 #23）** = 已初始化 + 桌面审批界面在场 → 放行至
    /// `disclosure_begin` 走一体化弹窗（锁态必弹窗——读规则在加密库内无法
    /// 预载，即使命中也弹，与 #67 inject 同款妥协）；锁态无 UI / 未初始化
    /// 库 → fail-closed `session.invalid`（不弹窗、不阻塞，headless 维持
    /// 现状）。
    pub(crate) fn disclosure_precheck(&self, token: Option<&[u8]>) -> bool {
        if self.vault_peek() {
            self.sessions.validate(token.unwrap_or(&[]))
        } else {
            lk_core::vault::vault_exists(&self.shared.dir) && self.gate.approval().available()
        }
    }

    /// 阶段①（命令锁内，非阻塞；spec §5.2 步骤 1-7）。
    ///
    /// 锁态分流（补充拍板 #23）：vault 未解锁 → 一体化解锁弹窗路径；解锁态
    /// → 既有裁决路径。两条路径在同一命令锁内切换，期间 vault **只可能从
    /// 解锁变锁定**（解锁需命令锁，锁屏线程只取 vault 写锁）——precheck 已
    /// 验令牌（解锁态）或被跳过（锁态）的语义不会因竞态被反转。
    pub(crate) fn disclosure_begin(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin {
        // 1) 参数解析（id 必填；channel 为可选审计来源标注，§8——缺省按
        //    对端来源，wsl-bridge 客户端标注优先，与 rule.* 同口径）
        let (item_id, channel_param) = match method {
            M_ITEM_GET => match parse_gate_params::<ItemGetParams>(&id, params) {
                Ok(p) => (p.id, p.channel),
                Err(line) => return GateBegin::Final(line),
            },
            M_ITEM_EXPORT => match parse_gate_params::<ItemExportParams>(&id, params) {
                Ok(p) => (p.id, p.channel),
                Err(line) => return GateBegin::Final(line),
            },
            _ => {
                return GateBegin::Final(rpc_string(RpcResponse::err(
                    id,
                    ERR_METHOD_NOT_FOUND,
                    MSG_METHOD_NOT_FOUND,
                    None,
                )))
            }
        };
        // 1') 锁定态（#23）：库加密中无法解析条目名 / 规则 / exportMeta——
        //     全部推迟到 finalize（临时 vault）。只做不依赖 vault 的
        //     fail-closed（unknown starter / 无 cwd；锁态无 K_audit，拒绝
        //     不写审计，与 #67 锁态拒绝同口径）。可用性已由 precheck 分派，
        //     此处仍复核（纵深防御）。
        if !self.vault_peek() {
            let starter = derive_starter(peer);
            let cwd =
                lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
            if starter == UNKNOWN_STARTER || cwd.is_empty() {
                return GateBegin::Final(rpc_string(authz_denied(id)));
            }
            if !self.gate.approval().available() {
                return GateBegin::Final(rpc_string(authz_denied(id)));
            }
            // 登记待审批（needs_unlock=true）+ 广播 authz.request
            // （needsUnlock=true，D 层弹窗同时展示主密码输入 + 授权栏）。
            // challenge 语义同 #67 注入一体化：一次性应答值，仅投桌面订阅者，
            // 回传必须原样带回（#78）。锁态不知道条目名，keys 空（finalize
            // 在临时 vault 上解析后写审计 target）。
            let kind = disclosure_kind(method);
            let request_id = self.open_gate_approval(
                ApprovalDraft {
                    starter: starter.clone(),
                    project_dir: cwd,
                    command: method.to_string(),
                    keys: vec![],
                    kind,
                    // #147：read/export 审批不带审批子类型（帧不含 subKind 字段）
                    sub_kind: None,
                    write_action: None,
                    export_meta: None,
                    fingerprint_mismatch: None,
                },
                GateEntry {
                    needs_unlock: true,
                    temp_vault: None,
                    kind: GateKind::Disclosure(PendingDisclosure {
                        method: method.to_string(),
                        item_id,
                        item_name: None,
                        starter,
                    }),
                },
            );
            return GateBegin::Pending { request_id };
        }
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
                    (Some(item.name().to_string()), meta)
                }
                Err(e) => return GateBegin::Final(rpc_string(self.err_response(id, &e))),
            }
        };
        // 3) 通道判定：desktop 内嵌直调 → 受信豁免直返（不登记审批；
        //    GUI 读值体验零变化，spec §3 第 1 行）
        if peer.origin == PeerOrigin::Desktop {
            let resp = match method {
                M_ITEM_GET => self.item_get_exec(id, item_id, "desktop", AuditChannel::Desktop),
                _ => self.item_export_exec(id, item_id, "desktop", AuditChannel::Desktop),
            };
            return GateBegin::Final(rpc_string(resp));
        }
        // 4) socket 通道：真实 starter + cwd（#66 归因链路复用；客户端自报
        //    字段不信任）；未知 → 第 1 层 fail-closed 拒绝（不弹窗、不留内容）
        let starter = derive_starter(peer);
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let channel = client_channel(channel_param.as_deref(), peer_channel(peer));
        if starter == UNKNOWN_STARTER || cwd.is_empty() {
            self.audit_gate(
                ActingVault::Shared,
                &starter,
                item_name.as_deref().unwrap_or(""),
                method,
                channel,
                AuditResult::Denied,
            );
            return GateBegin::Final(rpc_string(authz_denied(id)));
        }
        // 5) item.get：读规则匹配（spec §4）→ 命中静默放行 + 审计 allowed
        if method == M_ITEM_GET {
            let hit = {
                let shared = Arc::clone(&self.shared);
                let guard = shared.vault.read().unwrap();
                let me = guard.as_ref().unwrap();
                me.list_rules().unwrap_or_default().iter().any(|r| {
                    lk_core::authz::read_rule_matches(
                        r,
                        &cwd,
                        item_name.as_deref().unwrap_or_default(),
                    )
                })
            };
            if hit {
                let resp = self.item_get_exec(id, item_id, &starter, channel);
                return GateBegin::Final(rpc_string(resp));
            }
        }
        // 6) get 未命中 / export 恒弹窗：无审批界面 → fail-closed 立即拒绝
        if !self.gate.approval().available() {
            self.audit_gate(
                ActingVault::Shared,
                &starter,
                item_name.as_deref().unwrap_or(""),
                method,
                channel,
                AuditResult::Denied,
            );
            return GateBegin::Final(rpc_string(authz_denied(id)));
        }
        // 7) 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞；challenge
        //    语义同 inject——仅投递桌面订阅者，回传必须原样带回，#78）
        let kind = disclosure_kind(method);
        let request_id = self.open_gate_approval(
            ApprovalDraft {
                starter: starter.clone(),
                project_dir: cwd,
                command: method.to_string(),
                keys: vec![item_name.clone().unwrap_or_default()],
                kind,
                // #147：read/export 审批不带审批子类型（帧不含 subKind 字段）
                sub_kind: None,
                write_action: None,
                export_meta: if method == M_ITEM_EXPORT {
                    export_meta
                } else {
                    None
                },
                fingerprint_mismatch: None,
            },
            GateEntry {
                needs_unlock: false,
                temp_vault: None,
                kind: GateKind::Disclosure(PendingDisclosure {
                    method: method.to_string(),
                    item_id,
                    item_name,
                    starter,
                }),
            },
        );
        GateBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁；spec §5.3）：Allowed → 披露值/数据包 + 审计
    /// allowed（channel=approval 与 inject 同口径）；deny / timeout / 条目
    /// 被消费（极端竞态）→ `authz.denied` + 审计。等待期间锁定 →
    /// `session.invalid`（exec 内 vault 为空时保守失败，无法签名审计）。
    ///
    /// 锁定态一体化（#23）：统一注册表条目 `needs_unlock` 时（issue #148
    /// 起 needs_unlock/temp_vault 条目级承载）——
    /// - **等待期整库被解锁**（用户绕开弹窗直接解锁）→ finalize 走**常态
    ///   路径**（共享 vault 披露 + 共享 K_audit 审计，与解锁态同语义）；
    /// - 仍锁定 → 用审批回传时临时解锁的 vault（条目级 `temp_vault`）在
    ///   临时 vault 上披露，随后即毁（不置 shared.vault / 不签发令牌）；
    /// - deny / timeout → 无临时 vault（未解锁）→ 无 K_audit 可签名，不写
    ///   审计（与 #67 注入一体化拒绝同口径）。
    pub(crate) fn disclosure_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let removed = self.pending_gates.lock().unwrap().remove(&request_id);
        // 条目已被消费（极端竞态）→ 保守拒绝
        let Some(GateEntry {
            needs_unlock,
            temp_vault,
            kind: GateKind::Disclosure(p),
        }) = removed
        else {
            return rpc_string(authz_denied(id));
        };
        match decision {
            ApprovalDecision::Allowed => {
                if needs_unlock {
                    return if self.vault_peek() {
                        // 等待期整库被解锁 → 常态路径（共享 vault）
                        self.disclosure_finalize_normal(id, p)
                    } else {
                        // 仍锁定 → 临时 vault 单次披露
                        self.disclosure_finalize_unlock(id, p, temp_vault)
                    };
                }
                self.disclosure_finalize_normal(id, p)
            }
            ApprovalDecision::Denied | ApprovalDecision::Timeout => {
                // 拒绝/超时统一 denied（spec §8：不区分原因，防探测）。
                // 锁定态一体化条目：未解锁 → 无 K_audit 不可签名，不写审计
                // （与 #67 注入拒绝同口径）；解锁态条目照旧落审计。
                if !needs_unlock {
                    self.audit_gate(
                        ActingVault::Shared,
                        &p.starter,
                        p.item_name.as_deref().unwrap_or(""),
                        &p.method,
                        AuditChannel::Approval,
                        AuditResult::Denied,
                    );
                }
                rpc_string(authz_denied(id))
            }
        }
    }

    /// 常态路径 finalize（解锁态既有语义；锁定态一体化在等待期整库被解锁
    /// 时也走本路径——#23「finalize 走常态路径」，披露与审计均用共享 vault）。
    fn disclosure_finalize_normal(&mut self, id: Value, p: PendingDisclosure) -> String {
        // 等待期间锁定（手动/自动/锁屏/恢复）：vault 与 K_audit 已
        // 擦除，无法披露也无法签名审计 → 保守 `session.invalid`
        // （与 authz_finalize resolve_env 失败同口径；exec 不再 unwrap）
        if !self.vault_peek() {
            return rpc_string(session_invalid(id));
        }
        let resp = match p.method.as_str() {
            M_ITEM_GET => self.item_get_exec(id, p.item_id, &p.starter, AuditChannel::Approval),
            _ => self.item_export_exec(id, p.item_id, &p.starter, AuditChannel::Approval),
        };
        rpc_string(resp)
    }

    /// 锁定态一体化 finalize（#23）：**临时 vault**（`approval_result_unlock`
    /// 以正确主密码解锁后存入统一注册表条目）上执行披露——get/export exec
    /// 支持传入外部 vault 引用（`item_get_exec_from` / `item_export_exec_from`），
    /// 审计用临时 vault 的 K_audit 签名（channel=approval）。临时 vault 随
    /// 本函数结束即销毁——不置 shared.vault、不签发令牌、不写 session.token
    /// （#65 边界：本次交互不产生任何持久能力）。
    fn disclosure_finalize_unlock(
        &mut self,
        id: Value,
        p: PendingDisclosure,
        temp_vault: Option<UnlockedVault>,
    ) -> String {
        // 临时 vault 由 approval_result 以正确主密码解锁后存入；
        // 缺失（异常路径）→ 保守拒绝
        let Some(vault) = temp_vault else {
            return rpc_string(authz_denied(id));
        };
        let resp = match p.method.as_str() {
            M_ITEM_GET => {
                self.item_get_exec_from(&vault, id, p.item_id, &p.starter, AuditChannel::Approval)
            }
            _ => self.item_export_exec_from(
                &vault,
                id,
                p.item_id,
                &p.starter,
                AuditChannel::Approval,
            ),
        };
        // 临时 vault 随本函数结束 drop——临时解锁材料即用即毁
        rpc_string(resp)
    }
}

/// 统一「值披露拒绝」错误响应（`authz.denied` / -32017）。
pub(crate) fn authz_denied(id: Value) -> RpcResponse {
    RpcResponse::err(id, ERR_AUTHZ_DENIED, MSG_AUTHZ_DENIED, None)
}

// -------------------------------------------------------------------------
// 流程声明（issue #149：通用 deferred 编排器的注册项）
// -------------------------------------------------------------------------

/// 值披露门流程声明（issue #149）：预检 / begin / finalize 委托既有门方法，
/// 锁编排由 router.rs 通用 deferred 编排器统一承担。**不可 RePended**——
/// 披露 finalize 一步收尾，无二次审批路径。
pub(crate) struct DisclosureFlow;

impl crate::router::DeferredFlow for DisclosureFlow {
    fn precheck(&self, daemon: &Daemon, token: Option<&[u8]>) -> bool {
        daemon.disclosure_precheck(token)
    }

    fn begin(
        &self,
        daemon: &mut Daemon,
        method: &str,
        id: Value,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin {
        daemon.disclosure_begin(id, method, params, peer)
    }

    fn finalize(
        &self,
        daemon: &mut Daemon,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> DeferredOutcome {
        DeferredOutcome::Done(daemon.disclosure_finalize(id, request_id, decision))
    }

    fn rependable(&self) -> bool {
        false
    }
}

pub(crate) const DISCLOSURE_FLOW: DisclosureFlow = DisclosureFlow;
