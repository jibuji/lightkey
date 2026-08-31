//! rule.* 命令处理 + 授权门 vault 视图

use super::*;

impl Daemon {
    /// `rule.add`：跨命名空间归一化 → 校验 → canonicalize → 入库（vault
    /// 写锁）+ 审计（channel 区分 cli/desktop/wsl-bridge：客户端参数标注
    /// 优先，缺省按对端来源；starter 为真实调用方归因，#66；
    /// testing.md 第三层 #19 超长/非法拒绝）。
    pub(crate) fn rule_add(&mut self, id: Value, params: Value, caller: &CallerId) -> RpcResponse {
        let p: RuleAddParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // projectDir 入库基准（cross-subsystem.md §7.4，两侧同函数）：先过
        // 跨命名空间归一化——UNC / verbatim 包裹的 WSL 路径折算为
        // `wsl://<distro>/<rest>` 规范形；常规路径维持原语义。
        let project_dir_input = lk_core::path_ns::canonical_project_dir(&p.project_dir);
        // 规则能力类型（M2.9 值披露 §4）：缺省 inject；read 规则不绑定命令
        let capability = p
            .capability
            .as_deref()
            .unwrap_or(lk_core::model::RULE_CAPABILITY_INJECT);
        if let Err(e) =
            validate_rule_fields(capability, &project_dir_input, &p.name, &p.command, &p.keys)
        {
            return RpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "invalid params",
                Some(json!({ "detail": e })),
            );
        }
        let channel = client_channel(p.channel.as_deref(), caller.channel);
        // wsl:// 规范形直接入库（非本机 fs 路径）；常规路径仍以 canonical
        // 形态入库（解析符号链接），并经与运行时 cwd 判定同一个归一化函数
        // 剥离 Windows verbatim 前缀（§7.4 两侧同函数，存储形态 == 判定形态）
        let project_dir = if lk_core::path_ns::is_wsl_canonical(&project_dir_input) {
            project_dir_input.clone()
        } else {
            match std::fs::canonicalize(&project_dir_input) {
                Ok(c) => lk_core::path_ns::canonical_project_dir(&c.to_string_lossy()),
                Err(_) => {
                    return RpcResponse::err(
                        id,
                        ERR_INVALID_PARAMS,
                        "invalid params",
                        Some(
                            json!({ "detail": format!("projectDir 无法解析：{}", p.project_dir) }),
                        ),
                    )
                }
            }
        };
        let draft = RuleDraft {
            project_dir,
            name: p.name.clone(),
            command: p.command.clone(),
            keys: p.keys.clone(),
            capability: capability.to_string(),
        };
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.put_rule(draft, None) {
            Ok(rule) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: caller.starter.clone(),
                        target: "daemon".into(),
                        command: format!("rule.add {}", p.name),
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

    /// `rule.list`：解密态规则（规则库损坏 → fail-closed 报错）。
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

    /// `rule.remove`：软删除（墓碑，删除随同步传播）+ 审计。
    pub(crate) fn rule_remove(
        &mut self,
        id: Value,
        params: Value,
        caller: &CallerId,
    ) -> RpcResponse {
        let p: RuleRemoveParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let channel = client_channel(p.channel.as_deref(), caller.channel);
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.delete_rule(p.id) {
            Ok(_tomb) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: caller.starter.clone(),
                        target: "daemon".into(),
                        command: format!("rule.remove {}", p.id),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                RpcResponse::ok(id, json!({}))
            }
            Err(e) => self.err_response(id, &e),
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
