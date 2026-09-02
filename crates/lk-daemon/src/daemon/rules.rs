//! rule.* 命令处理 + 授权门 vault 视图 + 规则管理审批门（补充拍板 #22）。
//!
//! socket/pipe 通道的 `rule.add` / `rule.remove` 走桌面审批门（对称原则：
//! 授权的建立与撤销都是授权事件）——ApprovalDeferred 三阶段（ADR-0001）：
//! begin（命令锁内：参数校验 + 归一化 + id→规则解析 + 通道判定 + 登记/广播）
//! → 锁外等待决策 → finalize（重取命令锁：**TOCTOU 重校验** vault 解锁态与
//! 规则存在性后落盘 + 审计）。GUI desktop 直调受信豁免（设置页、读值弹窗
//! 「允许并为此项目记住」内部的 ruleAdd）；bridge 通道对端非 desktop 自然
//! 受门；`rule.list` 维持令牌门（只读元数据，M2.9「值是边界」同口径）。
//! 错误码复用 -32017 `authz.denied`（协议零新增）；锁态 `session.invalid`
//! 先行（规则在加密库内，锁定态无从谈起）。

use super::*;

// ---------------------------------------------------------------------------
// begin / finalize（规则管理审批门三阶段的锁内两段）
// ---------------------------------------------------------------------------

/// 规则门 begin 结果：最终响应（desktop 豁免 / 参数错误 / fail-closed 拒绝）
/// 或待审批（等待移出命令锁，G1）。
pub(crate) enum RuleBegin {
    Final(String),
    Pending { request_id: uuid::Uuid },
}

/// 规则门待办操作（begin 期已校验/归一化；finalize 重执行）。
pub(crate) enum PendingRuleOp {
    /// `rule.add`（project_dir 已 canonical / wsl:// 规范形）。Box 逃逸
    /// `large_enum_variant`（`RuleAddParams` 含可选指纹，相对 `Remove` 较大）。
    Add(Box<RuleAddParams>),
    /// `rule.remove`（目标规则 id；finalize 锁内重验存在性）。
    Remove(uuid::Uuid),
}

/// 解析后的操作 + 弹窗展示字段（remove 由 daemon 解析 id→规则补全）。
struct ParsedRuleOp {
    op: PendingRuleOp,
    /// 展示/审计用规则名（add：请求 name；remove：既有规则 name）。
    display_name: String,
    /// 展示用 keys（add：请求 keys；remove：既有规则 keys）。
    display_keys: Vec<String>,
    /// 展示用 projectDir（canonical / wsl:// 规范形）。
    display_project_dir: String,
}

/// 规则门第 3 层待办（等待期间由发起连接线程持有，锁外等待）。
pub(crate) struct PendingRuleChange {
    op: PendingRuleOp,
    /// 审计 command 摘要（`rule.add <name>` / `rule.remove <id>`）。
    command_summary: String,
    /// 真实启动者（#66 进程链回溯；finalize 审计 starter 用）。
    starter: String,
    /// begin 期判定决策将来自 E2E 自动批准（finalize 审计
    /// channel=auto-approve + command 附 requestId，补充拍板 #22）。
    via_auto: bool,
}

impl Daemon {
    /// 规则门预检：锁定 → `session.invalid` 先行（规则在加密 vault 内，
    /// 锁定态无从校验/落盘）；解锁态 = 令牌有效（与 disclosure_precheck 同型）。
    pub(crate) fn rule_precheck(&self, token: Option<&[u8]>) -> bool {
        self.vault_peek() && self.sessions.validate(token.unwrap_or(&[]))
    }

    /// 阶段①（命令锁内，非阻塞）：参数解析 + 校验 + 归一化（与既有 Inline
    /// 语义一致：无效参数原错误直返）→ 通道判定（desktop 直调豁免直执行）
    /// → socket 走 fail-closed 检查（未知启动者 / 无审批界面且无 E2E 自动
    /// 批准 → 立即拒绝 + 审计）→ 登记待审批 + 广播 `authz.request`。
    pub(crate) fn rule_begin(
        &mut self,
        id: Value,
        method: &str,
        params: Value,
        peer: &PeerInfo,
    ) -> RuleBegin {
        // 1) 参数解析 + 校验 + 归一化（remove 顺带解析 id→规则，供弹窗展示）
        let parsed = match self.rule_parse_and_validate(method, &params) {
            Ok(p) => p,
            Err(resp) => return RuleBegin::Final(rpc_string(*resp)),
        };
        // 客户端自报 channel 标注（审计来源；缺省按对端来源回退）
        let channel_param = params
            .get("channel")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        // 2) GUI desktop 直调受信豁免（人在 GUI 前；设置页 / 读值弹窗内部
        //    ruleAdd）：直接执行 + 审计（channel=desktop，现状语义不变）
        if peer.origin == PeerOrigin::Desktop {
            let channel = client_channel(channel_param.as_deref(), AuditChannel::Desktop);
            let command = parsed.command_summary();
            let starter = "desktop".to_string();
            let resp = self.rule_op_exec(id, &parsed.op, &starter, channel, &command);
            return RuleBegin::Final(rpc_string(resp));
        }
        // 3) socket 通道：真实 starter（#66 进程链回溯；客户端自报不信任）；
        //    未知 → fail-closed 拒绝（不弹窗，与 inject/披露同口径）
        let starter = derive_starter(peer);
        let channel = client_channel(channel_param.as_deref(), peer_channel(peer));
        let command = parsed.command_summary();
        if starter == UNKNOWN_STARTER {
            self.audit_rule_gate(&command, &starter, channel, AuditResult::Denied);
            return RuleBegin::Final(rpc_string(super::disclosure::authz_denied(id)));
        }
        // 4) 无审批界面（headless）且无 E2E 自动批准 → fail-closed 立即拒绝
        //    （不登记、不阻塞；仅规则审批可走 auto 通道，补充拍板 #22）
        let via_auto = self
            .gate
            .approval()
            .auto_approves(lk_core::authz::ApprovalKind::Rule);
        if !via_auto && !self.gate.approval().available() {
            self.audit_rule_gate(&command, &starter, channel, AuditResult::Denied);
            return RuleBegin::Final(rpc_string(super::disclosure::authz_denied(id)));
        }
        // 5) 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞；单一 kind
        //    + command 字段承载操作：`rule.add <name>` / `rule.remove <name>`，
        //    补充拍板 #22——E2E 自动批准分支不广播，无 UI 参与）
        let request_id = lk_core::crypto::random_uuid();
        let challenge = hex::encode(lk_core::crypto::random_array::<16>());
        let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
        let areq = ApprovalRequest {
            request_id,
            starter: starter.clone(),
            project_dir: parsed.display_project_dir.clone(),
            command: format!("{} {}", method, parsed.display_name),
            keys: parsed.display_keys.clone(),
            challenge,
            needs_unlock: false,
            kind: lk_core::authz::ApprovalKind::Rule,
            export_meta: None,
            fingerprint_mismatch: None,
        };
        self.gate.approval().open(&areq, expires_at);
        self.pending_rule.lock().unwrap().insert(
            request_id,
            PendingRuleChange {
                op: parsed.op,
                command_summary: command,
                starter,
                via_auto,
            },
        );
        RuleBegin::Pending { request_id }
    }

    /// 阶段③（重取命令锁）：Allowed → **锁内重校验（TOCTOU）**——30s 等待
    /// 窗内规则库可能被并发审批落盘或同步轮次改变，vault 解锁态与（remove
    /// 的）规则存在性失效则拒绝并落审计；通过则落盘 + 审计（channel=
    /// approval / auto-approve）。deny / timeout → `authz.denied` + 审计。
    pub(crate) fn rule_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let pending = self.pending_rule.lock().unwrap().remove(&request_id);
        let Some(p) = pending else {
            // 条目已被消费（极端竞态）→ 保守拒绝
            return rpc_string(super::disclosure::authz_denied(id));
        };
        match decision {
            ApprovalDecision::Allowed => {
                // TOCTOU 重校验①：vault 解锁态（等待期锁定 → K_audit 已擦除，
                // 无法签名审计，与披露 finalize 同口径保守 session.invalid）
                if !self.vault_peek() {
                    return rpc_string(session_invalid(id));
                }
                // TOCTOU 重校验②：remove 的目标规则仍存在（等待窗内被并发
                // 审批落盘 / 同步轮次应用远端变更改变）。存在性按**未删除**
                // 口径（`list_rules` 过滤墓碑；`get_rule` 含已删除，幂等
                // delete 会静默成功，不能用作重验）
                if let PendingRuleOp::Remove(rid) = &p.op {
                    let still_exists = {
                        let shared = Arc::clone(&self.shared);
                        let guard = shared.vault.read().unwrap();
                        guard
                            .as_ref()
                            .map(|v| {
                                v.list_rules()
                                    .map(|rs| rs.iter().any(|r| r.id == *rid))
                                    .unwrap_or(false)
                            })
                            .unwrap_or(false)
                    };
                    if !still_exists {
                        self.audit_rule_gate(
                            &p.command_summary,
                            &p.starter,
                            AuditChannel::Approval,
                            AuditResult::Denied,
                        );
                        return rpc_string(super::disclosure::authz_denied(id));
                    }
                }
                // 落盘 + 审计：弹窗批准 → channel=approval；E2E 自动批准 →
                // channel=auto-approve 且 command 附 requestId（含规则内容，
                // 测试通道绝不静默，补充拍板 #22）
                let (channel, audit_command) = if p.via_auto {
                    (
                        AuditChannel::AutoApprove,
                        format!("{} [auto-approve {}]", p.command_summary, request_id),
                    )
                } else {
                    (AuditChannel::Approval, p.command_summary.clone())
                };
                let resp = self.rule_op_exec(id, &p.op, &p.starter, channel, &audit_command);
                rpc_string(resp)
            }
            ApprovalDecision::Denied | ApprovalDecision::Timeout => {
                let result = match decision {
                    ApprovalDecision::Timeout => AuditResult::Timeout,
                    ApprovalDecision::Denied => AuditResult::Denied,
                    ApprovalDecision::Allowed => unreachable!("上方已分派"),
                };
                self.audit_rule_gate(
                    &p.command_summary,
                    &p.starter,
                    AuditChannel::Approval,
                    result,
                );
                rpc_string(super::disclosure::authz_denied(id))
            }
        }
    }

    /// 参数解析 + 校验 + 归一化（add：跨命名空间归一化 → 字段校验 →
    /// canonicalize；remove：id→规则解析，补全 name/keys/projectDir 供弹窗
    /// 展示）。无效参数 / 条目不存在 → 原错误直返（与既有 Inline 语义一致）。
    fn rule_parse_and_validate(
        &self,
        method: &str,
        params: &Value,
    ) -> std::result::Result<ParsedRuleOp, Box<RpcResponse>> {
        match method {
            M_RULE_ADD => {
                let p: RuleAddParams = match serde_json::from_value(params.clone()) {
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
                // projectDir 入库基准（cross-subsystem.md §7.4，两侧同函数）：
                // 先过跨命名空间归一化——UNC / verbatim 包裹的 WSL 路径折算为
                // `wsl://<distro>/<rest>` 规范形；常规路径维持原语义。
                let project_dir_input = lk_core::path_ns::canonical_project_dir(&p.project_dir);
                let capability = p
                    .capability
                    .as_deref()
                    .unwrap_or(lk_core::model::RULE_CAPABILITY_INJECT);
                // 写动作子集（write-gate.md §7）：capability=write 时取参数
                // （缺省 create+update，与 serde 缺省一致）；capability !=
                // write 时忽略——按缺省落库（匹配函数按 capability 过滤）。
                let actions = if capability == lk_core::model::RULE_CAPABILITY_WRITE {
                    p.actions
                        .clone()
                        .unwrap_or_else(lk_core::model::default_rule_actions)
                } else {
                    lk_core::model::default_rule_actions()
                };
                if let Err(e) = validate_rule_fields(
                    capability,
                    &project_dir_input,
                    &p.name,
                    &p.command,
                    &p.keys,
                    &actions,
                ) {
                    return Err(Box::new(RpcResponse::err(
                        Value::Null,
                        ERR_INVALID_PARAMS,
                        "invalid params",
                        Some(json!({ "detail": e })),
                    )));
                }
                // wsl:// 规范形直接入库（非本机 fs 路径）；常规路径仍以
                // canonical 形态入库（解析符号链接），并经与运行时 cwd 判定
                // 同一个归一化函数剥离 Windows verbatim 前缀（存储形态 ==
                // 判定形态）
                let project_dir = if lk_core::path_ns::is_wsl_canonical(&project_dir_input) {
                    project_dir_input.clone()
                } else {
                    match std::fs::canonicalize(&project_dir_input) {
                        Ok(c) => lk_core::path_ns::canonical_project_dir(&c.to_string_lossy()),
                        Err(_) => {
                            return Err(Box::new(RpcResponse::err(
                                Value::Null,
                                ERR_INVALID_PARAMS,
                                "invalid params",
                                Some(json!({ "detail": format!(
                                    "projectDir 无法解析：{}", p.project_dir
                                ) })),
                            )))
                        }
                    }
                };
                Ok(ParsedRuleOp {
                    op: PendingRuleOp::Add(Box::new(RuleAddParams {
                        project_dir: project_dir.clone(),
                        name: p.name.clone(),
                        command: p.command.clone(),
                        keys: p.keys.clone(),
                        capability: p.capability.clone(),
                        // 校验后的有效 actions（write=参数展开缺省；其余=缺省）
                        actions: Some(actions),
                        channel: p.channel.clone(),
                        // M2.98 指纹绑定请求（请求侧仅声明「绑哪个 exe」；daemon
                        // 在审批 finalize 侧重算后落库——身份绑定.md §5.3）
                        fingerprint: p.fingerprint.clone(),
                    })),
                    display_name: p.name.clone(),
                    display_keys: p.keys.clone(),
                    display_project_dir: project_dir,
                })
            }
            M_RULE_REMOVE => {
                let p: RuleRemoveParams = match serde_json::from_value(params.clone()) {
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
                // id→规则解析（弹窗展示既有规则的名称/keys/项目目录，
                // value-disclosure 同款「daemon 侧补全」）
                let rule = {
                    let shared = Arc::clone(&self.shared);
                    let guard = shared.vault.read().unwrap();
                    match guard.as_ref() {
                        Some(v) => v.get_rule(p.id),
                        None => Err(Error::SessionInvalid),
                    }
                };
                match rule {
                    Ok(r) => Ok(ParsedRuleOp {
                        op: PendingRuleOp::Remove(p.id),
                        display_name: r.name.clone(),
                        display_keys: r.keys.clone(),
                        display_project_dir: r.project_dir.clone(),
                    }),
                    Err(e) => Err(Box::new(self.err_response(Value::Null, &e))),
                }
            }
            _ => Err(Box::new(RpcResponse::err(
                Value::Null,
                ERR_METHOD_NOT_FOUND,
                MSG_METHOD_NOT_FOUND,
                None,
            ))),
        }
    }

    /// 落盘 + 审计 + 响应（desktop 豁免与 finalize 批准后共用）。
    /// `audit_command` 由调用方给定（auto-approve 路径附 requestId）。
    fn rule_op_exec(
        &mut self,
        id: Value,
        op: &PendingRuleOp,
        starter: &str,
        channel: AuditChannel,
        audit_command: &str,
    ) -> RpcResponse {
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let Some(me) = guard.as_mut() else {
            // 竞态：取写锁前被锁屏线程锁定（vault.lock 的守护进程命令锁
            // 之外的路径）→ 保守 session.invalid（与披露 finalize 同口径）
            return session_invalid(id);
        };
        match op {
            PendingRuleOp::Add(p) => {
                let capability = p
                    .capability
                    .as_deref()
                    .unwrap_or(lk_core::model::RULE_CAPABILITY_INJECT);
                // M2.98 程序指纹（§5.3「以新指纹重新授权」）：绑定请求带指纹时，
                // daemon **不信任客户端上报的 sha/size**——在批准后的 finalize
                // 侧重算（canonicalize + stat + 流式 SHA-256，走缓存）。重算失败
                // （exe 不可解析/不可读）→ 无法绑定 → 判失败（fail-closed）。
                let fingerprint = match p.fingerprint.as_ref() {
                    Some(fp) => {
                        match crate::identity::recompute_fingerprint(
                            &fp.exe_path,
                            &mut self.fingerprint_cache,
                        ) {
                            Some(rf) => Some(rf),
                            None => {
                                return RpcResponse::err(
                                    id,
                                    ERR_INVALID_PARAMS,
                                    "invalid params",
                                    Some(json!({ "detail": format!(
                                        "无法解析/读取要绑定的可执行文件：{}", fp.exe_path
                                    ) })),
                                )
                            }
                        }
                    }
                    None => None,
                };
                let draft = RuleDraft {
                    project_dir: p.project_dir.clone(),
                    name: p.name.clone(),
                    command: p.command.clone(),
                    keys: p.keys.clone(),
                    capability: capability.to_string(),
                    // 校验层已归一（write=参数/缺省；capability!=write=缺省
                    // 忽略），此处原样落库（write-gate.md §7，issue #114）
                    actions: p
                        .actions
                        .clone()
                        .unwrap_or_else(lk_core::model::default_rule_actions),
                    // 指纹：daemon 侧重算后的固化值（见上方 recompute）。
                    fingerprint,
                };
                match me.put_rule(draft, None) {
                    Ok(rule) => {
                        let _ = self.audit.append(
                            me.keys(),
                            &EventInput {
                                starter: starter.to_string(),
                                target: "daemon".into(),
                                command: audit_command.to_string(),
                                result: AuditResult::Allowed,
                                channel,
                                old_key_id: None,
                                new_key_id: None,
                            },
                        );
                        let result = RuleAddResult { rule };
                        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
                    }
                    Err(e) => self.err_response(id, &e),
                }
            }
            PendingRuleOp::Remove(rid) => match me.delete_rule(*rid) {
                Ok(_tomb) => {
                    let _ = self.audit.append(
                        me.keys(),
                        &EventInput {
                            starter: starter.to_string(),
                            target: "daemon".into(),
                            command: audit_command.to_string(),
                            result: AuditResult::Allowed,
                            channel,
                            old_key_id: None,
                            new_key_id: None,
                        },
                    );
                    RpcResponse::ok(id, json!({}))
                }
                Err(e) => self.err_response(id, &e),
            },
        }
    }

    /// 规则门拒绝/超时审计（失败路径，现状仅成功路径写；补充拍板 #22）：
    /// command=`rule.add <name>` / `rule.remove <id>`，starter/channel=真实
    /// 归因。K_audit 签名；已锁定（K_audit 擦除）→ 跳过（与授权路径同口径）。
    fn audit_rule_gate(
        &self,
        command: &str,
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
                target: "daemon".into(),
                command: command.to_string(),
                result,
                channel,
                old_key_id: None,
                new_key_id: None,
            },
        );
    }

    /// `rule.list`：解密态规则（规则库损坏 → fail-closed 报错）。
    /// 维持令牌门（只读元数据，M2.9「值是边界，名称如实降级」同口径）。
    pub(crate) fn rule_list(&mut self, id: Value, params: Value, caller: &CallerId) -> RpcResponse {
        let channel = match serde_json::from_value::<RuleListParams>(params) {
            Ok(p) => client_channel(p.channel.as_deref(), caller.channel),
            Err(_) => caller.channel,
        };
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        match me.list_rules() {
            Ok(rules) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: caller.starter.clone(),
                        target: "daemon".into(),
                        command: M_RULE_LIST.into(),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                let result = RuleListResult { rules };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }
}

impl ParsedRuleOp {
    /// 审计 command 摘要（与既有 rule.* 审计口径一致：add 记 name，
    /// remove 记 id）。
    fn command_summary(&self) -> String {
        match &self.op {
            PendingRuleOp::Add(p) => format!("rule.add {}", p.name),
            PendingRuleOp::Remove(rid) => format!("rule.remove {}", rid),
        }
    }
}

/// 授权门第 1/2 层需要的 vault 视图（守护进程 vault 读锁内实现）。
/// secrets 为**单次扫描**产物（一次 evaluate 只扫一遍 vault，避免逐 key 扫描）。
pub(crate) struct VaultRuleView<'a> {
    pub(crate) vault: &'a UnlockedVault,
    pub(crate) secrets: std::collections::HashMap<String, String>,
}

impl lk_core::authz::RuleVault for VaultRuleView<'_> {
    fn rules(&self) -> Result<Vec<Rule>> {
        self.vault.list_rules()
    }
    fn secret_value(&self, key_name: &str) -> Result<Option<String>> {
        Ok(self.secrets.get(key_name).cloned())
    }
}

/// `rule.list` 参数（可选 channel 标注）。
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleListParams {
    #[serde(default)]
    channel: Option<String>,
}
