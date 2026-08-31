//! item.* / audit.* 命令处理

use super::*;

impl Daemon {
    pub(crate) fn item_list(&mut self, id: Value, caller: &CallerId) -> RpcResponse {
        // list() 需 &mut（索引自愈）→ 写锁；锁只保护内存一致性，本地操作
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.list() {
            Ok(items) => {
                let _ = self
                    .audit
                    .append(me.keys(), &caller.event(M_ITEM_LIST, AuditResult::Allowed));
                let result = ItemListResult { items };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    /// `item.get` 披露执行核心（M2.9 值披露：值离开守护进程=授权事件）。
    /// 调用方已过裁决（desktop 豁免 / 读规则命中 / 弹窗批准，见
    /// `daemon/disclosure.rs`）；审计 command=`item.get`、target=条目名
    /// （spec §8），channel/starter 由裁决路径给出。
    pub(crate) fn item_get_exec(
        &mut self,
        id: Value,
        item_id: uuid::Uuid,
        starter: &str,
        channel: AuditChannel,
    ) -> RpcResponse {
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        match me.get(item_id) {
            Ok(item) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: starter.to_string(),
                        target: item.name().to_string(),
                        command: M_ITEM_GET.into(),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                RpcResponse::ok(id, serde_json::to_value(item).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    /// `item.export` 披露执行核心（恒弹窗路径的批准后披露）；审计
    /// command=`item.export`、target=条目名（spec §8）。
    pub(crate) fn item_export_exec(
        &mut self,
        id: Value,
        item_id: uuid::Uuid,
        starter: &str,
        channel: AuditChannel,
    ) -> RpcResponse {
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        // 条目名先按 id 解析（target=条目名，与附件文件名可不同）
        let name = match me.get(item_id) {
            Ok(item) => item.name().to_string(),
            Err(e) => return self.err_response(id, &e),
        };
        match me.export(item_id) {
            Ok(bundle) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: starter.to_string(),
                        target: name,
                        command: M_ITEM_EXPORT.into(),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                let result = ItemExportResult {
                    name: bundle.name,
                    mime: bundle.mime,
                    size: bundle.size,
                    data: base64::engine::general_purpose::STANDARD.encode(bundle.data),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn item_put(&mut self, id: Value, params: Value, caller: &CallerId) -> RpcResponse {
        let p: ItemPutParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let kind = p.item.kind().as_str();
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.put(p.id, p.item, p.expected_revision) {
            Ok(item) => {
                let _ = self.audit.append(
                    me.keys(),
                    &caller.event(
                        format!("{} {} <redacted>", M_ITEM_PUT, kind),
                        AuditResult::Allowed,
                    ),
                );
                let result = ItemPutResult { item };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn item_delete(
        &mut self,
        id: Value,
        params: Value,
        caller: &CallerId,
    ) -> RpcResponse {
        let p: ItemDeleteParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.delete(p.id) {
            Ok(_tomb) => {
                let _ = self.audit.append(
                    me.keys(),
                    &caller.event(format!("{} {}", M_ITEM_DELETE, p.id), AuditResult::Allowed),
                );
                RpcResponse::ok(id, json!({}))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn audit_list(
        &mut self,
        id: Value,
        params: Value,
        caller: &CallerId,
    ) -> RpcResponse {
        let p: AuditListParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        let events = self.audit.read();
        let _ = self
            .audit
            .append(me.keys(), &caller.event(M_AUDIT_LIST, AuditResult::Allowed));
        match events {
            Ok(all) => {
                let total = all.len();
                let events = match p.limit {
                    Some(n) => all
                        .into_iter()
                        .rev()
                        .take(n)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect(),
                    None => all,
                };
                let result = AuditListResult { events, total };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn audit_verify(&mut self, id: Value) -> RpcResponse {
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        let keys = me.keys();
        // 仅当前密钥可验证的部分（轮换点前事件需旧钥，M0 如实报告）
        let verified = match self.audit.verify(keys, &|_| None) {
            Ok(v) => v,
            Err(e) => {
                return RpcResponse::err(
                    id,
                    ERR_AUDIT_VERIFY,
                    MSG_AUDIT_VERIFY,
                    Some(json!({ "detail": e.to_string() })),
                )
            }
        };
        // 锚点交叉核对（issue #75）：读链尾 ordinal/last_hmac → 对比锚点。
        // 截断/锚点缺失 → 报 truncated，CLI 据此退出非零。
        let events = self.audit.read().unwrap_or_default();
        let chain_ordinal = events.len();
        let last_hmac = events.last().map(|e| e.hmac.clone()).unwrap_or_default();
        let (anchor_value, anchor_degraded) = match self.anchor.load() {
            Ok(a) => (a, self.anchor.degraded()),
            Err(_) => (None, true),
        };
        let truncated = !matches!(
            lk_core::audit_anchor::check_anchor(
                chain_ordinal as u64,
                &last_hmac,
                anchor_value.as_ref(),
            ),
            lk_core::audit_anchor::AnchorCheck::Ok
                | lk_core::audit_anchor::AnchorCheck::AnchorBehind(_)
        );
        let anchor_ok = !truncated;
        let anchor_ordinal = anchor_value.map(|a| a.ordinal);
        let result = AuditVerifyResult {
            verified,
            anchor_ok,
            anchor_degraded,
            truncated,
            chain_ordinal,
            anchor_ordinal,
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }
}
