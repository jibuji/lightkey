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
//!
//! 五件套下沉（issue #148）：begin 结果（GateBegin）/ 统一注册表（GateEntry）/
//! 审批单点铸造 / 审计辅助（audit_gate）/ 参数解析辅助出自 daemon/gate_kit.rs。

use super::*;

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

    /// 阶段①（命令锁内，非阻塞；write-gate.md §5.3）。返回**分层裁决
    /// 结果**（issue #167）：拒绝以 reason 承载（字节由门声明渲染器唯一
    /// 渲染——本门恒 `authz.denied`），放行/协议直返为已渲染负载。
    ///
    /// 1. 参数解析（无效参数原错误直返，与既有 Inline 语义一致）；
    /// 2. 解析目标条目名（update/delete 按 id；不存在 → `item.not_found`
    ///    现状语义）+ action 权威派生（id None=create / Some=update）；
    /// 3. desktop 直调受信豁免 → 直接执行（不登记审批）；
    /// 4. socket：真实 starter + cwd（#66 归因链路）；未知 → fail-closed
    ///    拒绝不弹窗；
    /// 5. 写规则匹配（create/update；**delete 跳过**恒弹窗）→ 命中静默放行；
    /// 6. 未命中：无审批界面 → 立即拒绝；否则登记待审批（审批注册表，
    ///    challenge 防伪 #78）+ 广播 `authz.request`。
    pub(crate) fn write_begin(
        &mut self,
        method: &str,
        id: Value,
        params: Value,
        peer: &PeerInfo,
    ) -> GateBegin {
        // 1) 参数解析 + action 权威派生（§5.2）
        let parsed = match self.write_parse(method, &params) {
            Ok(p) => p,
            Err(line) => return GateBegin::Final(line),
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
                    Err(e) => return GateBegin::Final(rpc_string(self.err_response(id, &e))),
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
            return GateBegin::Final(rpc_string(resp));
        }
        // 4) socket 通道：真实 starter + cwd（#66 归因链路复用；客户端自报
        //    字段不信任）；未知 → 第 1 层 fail-closed 拒绝（不弹窗、不留内容）
        let starter = derive_starter(peer);
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let channel = peer_channel(peer);
        let command_summary = write_command_summary(&parsed.op, &target);
        if starter == UNKNOWN_STARTER {
            self.audit_gate(
                ActingVault::Shared,
                &starter,
                &target,
                &command_summary,
                channel,
                AuditResult::Denied,
            );
            return GateBegin::Deny(GateDeny::UnknownStarter);
        }
        if cwd.is_empty() {
            self.audit_gate(
                ActingVault::Shared,
                &starter,
                &target,
                &command_summary,
                channel,
                AuditResult::Denied,
            );
            return GateBegin::Deny(GateDeny::NoCwd);
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
                return GateBegin::Final(rpc_string(resp));
            }
        }
        // 6) 无审批界面（headless）→ fail-closed 立即拒绝（不登记、不阻塞；
        //    E2E 自动批准不扩到写门——弹窗路径由集成测试覆盖，拍板 #24）
        if !self.approval_available() {
            self.audit_gate(
                ActingVault::Shared,
                &starter,
                &target,
                &command_summary,
                channel,
                AuditResult::Denied,
            );
            return GateBegin::Deny(GateDeny::NoUi);
        }
        // 7) 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）：kind=
        //    write、command=`item.put/delete <name>`（展示用）、keys=单元素
        //    [目标条目名]、project_dir=cwd、needs_unlock=false、export_meta
        //    恒 None（§5.3 步骤 7 / §6）。challenge 语义同 inject——仅投递
        //    桌面订阅者，回传必须原样带回（#78）。write_action=begin 期
        //    权威派生的动作，随帧回带 `writeAction`——前端「记住」据此生成
        //    `actions=[当前动作]` 最小写规则（§6 / #137，RPC 仍不拆）。
        let display_command = format!(
            "{} {}",
            match parsed.op {
                PendingWriteOp::Delete(_) => M_ITEM_DELETE,
                _ => M_ITEM_PUT,
            },
            target
        );
        let request_id = self.open_gate_approval(
            {
                // 写审批携带门事实：subKind（item.put / item.delete，#147）
                // + writeAction（begin 期权威派生，#137；delete 无动作）——
                // 九字段克隆单点构造（issue #167）。
                let draft = ApprovalDraft::new(
                    starter.clone(),
                    cwd,
                    display_command,
                    vec![target.clone()],
                    lk_core::authz::ApprovalKind::Write,
                )
                .with_sub_kind(match parsed.op {
                    PendingWriteOp::Delete(_) => lk_core::authz::ApprovalSubKind::ItemDelete,
                    _ => lk_core::authz::ApprovalSubKind::ItemPut,
                });
                match write_action(&parsed.op) {
                    Some(a) => draft.with_write_action(a),
                    None => draft,
                }
            },
            // 常规审批条目（issue #150：`GateEntry::approval` 显式声明写门
            // 无需一体化解锁——写门无解锁窗，write-gate.md §5.3 拍板保留）
            GateEntry::approval(GateKind::Write(PendingWrite {
                op: parsed.op,
                draft: parsed.draft,
                expected_revision: parsed.expected_revision,
                command_summary,
                target,
                starter,
            })),
        );
        GateBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁；write-gate.md §5.4）：Allowed → **锁内 TOCTOU
    /// 重校验**（等待窗内可能被并发审批落盘 / 同步轮次应用远端变更 / 锁定）
    /// → 执行 + 审计（channel=approval）；deny / timeout → 决策结局拒绝尾 +
    /// 审计；重验失效 → 执行层保守拒绝（issue #167 分层：TOCTOU 失效是执行
    /// 失败而非 Denied 决策）；等待期锁定 → `session.invalid`（执行失败）。
    /// 返回分层结果，字节由编排器经门声明渲染器收线。
    pub(crate) fn write_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> DeferredOutcome {
        // finalize = 审批注册表唯一消费移除点（拍板 #28 候选 2 三拍之三）
        let removed = self.shared.approvals.remove(&request_id);
        // 条目已被消费（极端竞态）→ 保守拒绝（决策结局）
        let Some(ApprovalEntry {
            kind: GateKind::Write(p),
            ..
        }) = removed
        else {
            return DeferredOutcome::Denied(GateDeny::Rejected);
        };
        match decision {
            ApprovalDecision::Allowed => {
                // TOCTOU 重校验①：vault 解锁态（等待期锁定 → K_audit 已擦除，
                // 无法签名审计，与披露/规则门 finalize 同口径保守 session.invalid）
                if !self.vault_peek() {
                    return DeferredOutcome::SessionInvalid;
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
                        self.audit_gate(
                            ActingVault::Shared,
                            &p.starter,
                            &p.target,
                            &p.command_summary,
                            AuditChannel::Approval,
                            AuditResult::Denied,
                        );
                        return DeferredOutcome::ExecutionDenied(GateDeny::Rejected);
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
                DeferredOutcome::Executed(rpc_string(resp))
            }
            ApprovalDecision::Denied | ApprovalDecision::Timeout => {
                // 拒绝/超时统一 denied（§8：不区分原因防探测，与值披露同口径）
                self.audit_gate(
                    ActingVault::Shared,
                    &p.starter,
                    &p.target,
                    &p.command_summary,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                DeferredOutcome::Denied(if decision == ApprovalDecision::Timeout {
                    GateDeny::Timeout
                } else {
                    GateDeny::Rejected
                })
            }
        }
    }

    /// 参数解析 + action 权威派生（`ItemPutParams.id` None=create /
    /// Some=update，§5.2——不信任客户端自报；协议结构零变更）。解析错误
    /// 现状为 null id（零行为变更，gate-kit 辅助照传）。
    fn write_parse(
        &self,
        method: &str,
        params: &Value,
    ) -> std::result::Result<ParsedWrite, String> {
        match method {
            M_ITEM_PUT => {
                let p: ItemPutParams = parse_gate_params(&Value::Null, params.clone())?;
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
                let p: ItemDeleteParams = parse_gate_params(&Value::Null, params.clone())?;
                Ok(ParsedWrite {
                    op: PendingWriteOp::Delete(p.id),
                    draft: None,
                    expected_revision: None,
                })
            }
            _ => Err(rpc_string(RpcResponse::err(
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

// -------------------------------------------------------------------------
// 门声明（issue #167：静态声明取代 DeferredFlow trait 空壳；注册于
// router.rs 流程注册表）
// -------------------------------------------------------------------------

/// 写入门拒绝响应渲染器（issue #167）：(门 × 锁态/会话态 × reason) → 字节
/// 的**唯一决定点**。本门一切拒绝统一 `authz.denied`(-32017)（§5.5 协议
/// 零新增；与 inject 的 `ok{allowed,reason}` 字节不同，不得跨门压平）。
/// 渲染器拿 daemon 上下文是防「决策 → 字节」全局纯函数的结构钩子
/// （golden 表钉住全部字节，tests/gate_golden.rs）。
fn render_write_deny(_daemon: &Daemon, id: Value, _deny: GateDeny) -> String {
    rpc_string(super::disclosure::authz_denied(id))
}

/// 写入门静态声明：**不可 RePended**——写门 finalize 一步收尾（TOCTOU
/// 重校验后执行），无二次审批路径（写门无解锁窗，write-gate.md §5.3
/// 拍板保留）；**无需一体化解锁**（issue #150 显式声明，产品决策留档）。
pub(crate) static WRITE_GATE: crate::router::GateDecl = crate::router::GateDecl {
    name: "write(item.put/item.delete)",
    rependable: false,
    unlock_supported: false,
    precheck: Daemon::write_precheck,
    begin: Daemon::write_begin,
    finalize: Daemon::write_finalize,
    render_deny: render_write_deny,
};
