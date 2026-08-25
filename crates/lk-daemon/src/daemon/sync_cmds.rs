//! sync.poll / 同步触发预检

use super::*;
use crate::sync::{run_sync_round, sync_fail_response};

impl Daemon {
    pub(crate) fn sync_poll(&mut self, id: Value) -> RpcResponse {
        let sync = self.shared.sync.lock().unwrap();
        let result = SyncPollResult {
            summary: sync.state.last_summary.clone(),
            watermark: sync.state.watermark.clone(),
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    /// OutsideLock 策略的直调形态：持命令锁跑完整轮次（会话预检已由
    /// require_session 完成；单线程场景与 route() 主缝的锁外编排请求/响应
    /// 一致，仅少了不必要持有的解锁窗口）。
    pub(crate) fn sync_trigger_inline(&mut self, id: Value) -> RpcResponse {
        match run_sync_round(&self.shared) {
            Ok(summary) => {
                RpcResponse::ok(id, serde_json::to_value(summary).unwrap_or(Value::Null))
            }
            Err(e) => sync_fail_response(id, &e),
        }
    }

    /// `sync.trigger` 无锁路径的会话预检（命令锁内调用）：解锁态 + 令牌有效。
    pub fn trigger_precheck(&self, token: Option<&[u8]>) -> bool {
        self.vault_peek() && self.sessions.validate(token.unwrap_or(&[]))
    }
}
