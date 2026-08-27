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
                    .append(me.keys(), &caller.event("item.list", AuditResult::Allowed));
                let result = ItemListResult { items };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn item_get(&mut self, id: Value, params: Value, caller: &CallerId) -> RpcResponse {
        let p: ItemGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        match me.get(p.id) {
            Ok(item) => {
                let _ = self.audit.append(
                    me.keys(),
                    &caller.event(format!("item.get {}", p.id), AuditResult::Allowed),
                );
                RpcResponse::ok(id, serde_json::to_value(item).unwrap_or(Value::Null))
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
                        format!("item.put {} <redacted>", kind),
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
                    &caller.event(format!("item.delete {}", p.id), AuditResult::Allowed),
                );
                RpcResponse::ok(id, json!({}))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    pub(crate) fn item_export(
        &mut self,
        id: Value,
        params: Value,
        caller: &CallerId,
    ) -> RpcResponse {
        let p: ItemExportParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        match me.export(p.id) {
            Ok(bundle) => {
                let _ = self.audit.append(
                    me.keys(),
                    &caller.event(format!("item.export {}", p.id), AuditResult::Allowed),
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
            .append(me.keys(), &caller.event("audit.list", AuditResult::Allowed));
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
