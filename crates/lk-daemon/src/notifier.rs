//! 通知桥（M2 决策 #3 A）：守护进程 → 订阅连接的推送通道。
//!
//! - [`Notifier`] 是 [`EventSink`](lk_core::bus::EventSink) 实现，订阅
//!   `CoreServices::bus()`，把 [`VaultEvent`] 翻译成 JSON-RPC **notification
//!   帧**（无 `id`，一行一帧）广播给订阅连接；
//! - **`authz.request` 仅投递给桌面来源的订阅者**（#72/#78 方案 A：帧里的
//!   一次性 challenge 是审批应答凭据，不得离开受信桌面通道；`has_ui` 同样
//!   只数桌面订阅者——socket 订阅者收不到该帧也就无法自我批准）；
//! - **非阻塞**（总线契约）：广播只做内存 channel 投递，socket 写入由每个
//!   订阅连接自己的 writer 线程承担（见 [`transport::PushHub`]）；
//! - `item.changed` 帧的 `kind` 映射回协议字段 `type`（bus.rs 契约）。

use std::sync::Arc;

use lk_core::bus::{EventSink, VaultEvent};
use serde_json::json;

use crate::transport::PushHub;

/// 事件 → notification 帧（协议面字段，`docs/plugin-architecture.md` §5.2）。
pub fn frame_for_event(event: &VaultEvent) -> String {
    let (method, params) = match event {
        VaultEvent::ItemChanged {
            item_id,
            revision_date,
            kind,
            deleted,
        } => (
            "item.changed",
            json!({
                "itemId": item_id,
                "revisionDate": revision_date,
                "type": kind,
                "deleted": deleted,
            }),
        ),
        VaultEvent::SessionUnlocked { via } => ("session.unlocked", json!({ "via": via.as_str() })),
        VaultEvent::SessionLocked { reason } => {
            ("session.locked", json!({ "reason": reason.as_str() }))
        }
        VaultEvent::AuthzRequest {
            request_id,
            starter,
            project_dir,
            command,
            keys,
            challenge,
        } => (
            "authz.request",
            json!({
                "requestId": request_id,
                "starter": starter,
                "projectDir": project_dir,
                "command": command,
                "keys": keys,
                "challenge": challenge,
            }),
        ),
    };
    json!({ "jsonrpc": "2.0", "method": method, "params": params }).to_string()
}

/// 是否为仅桌面可见的帧（#72/#78：`authz.request` 携带一次性审批挑战，
/// 只投给桌面来源订阅者——socket 订阅者不计入审批界面、也不得见到挑战）。
fn desktop_only(event: &VaultEvent) -> bool {
    matches!(event, VaultEvent::AuthzRequest { .. })
}

/// 通知桥（EventSink）：Rust 事件 → notification 帧 → 订阅连接广播。
/// 回调内只做内存投递（非阻塞，符合总线契约）。
pub struct Notifier {
    hub: Arc<PushHub>,
}

impl Notifier {
    pub fn new(hub: Arc<PushHub>) -> Notifier {
        Notifier { hub }
    }
}

impl EventSink for Notifier {
    fn on_event(&self, event: &VaultEvent) {
        let frame = frame_for_event(event);
        if desktop_only(event) {
            self.hub.broadcast_desktop(&frame);
        } else {
            self.hub.broadcast(&frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::bus::{LockReason, SessionVia};

    #[test]
    fn frames_match_protocol_contract() {
        // item.changed：kind → 协议字段 type
        let frame = frame_for_event(&VaultEvent::ItemChanged {
            item_id: uuid::Uuid::nil(),
            revision_date: "2026-08-16T00:00:00.000000Z".into(),
            kind: "login".into(),
            deleted: false,
        });
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["method"], "item.changed");
        assert!(v.get("id").is_none(), "notification 无 id");
        assert_eq!(v["params"]["type"], "login");
        assert_eq!(v["params"]["itemId"], uuid::Uuid::nil().to_string());

        let frame = frame_for_event(&VaultEvent::SessionLocked {
            reason: LockReason::Timeout,
        });
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["method"], "session.locked");
        assert_eq!(v["params"]["reason"], "timeout");

        let frame = frame_for_event(&VaultEvent::SessionUnlocked {
            via: SessionVia::Password,
        });
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["method"], "session.unlocked");
        assert_eq!(v["params"]["via"], "password");

        // authz.request：字段对齐 plugin-architecture.md §5.2；challenge 仅
        // 随本帧走桌面通道（#78 方案 A/B）
        let frame = frame_for_event(&VaultEvent::AuthzRequest {
            request_id: uuid::Uuid::nil(),
            starter: "/bin/zsh".into(),
            project_dir: "/proj".into(),
            command: "npm publish".into(),
            keys: vec!["NPM_TOKEN".into()],
            challenge: "chal-1".into(),
        });
        let v: serde_json::Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(v["method"], "authz.request");
        assert_eq!(v["params"]["starter"], "/bin/zsh");
        assert_eq!(v["params"]["projectDir"], "/proj");
        assert_eq!(v["params"]["command"], "npm publish");
        assert_eq!(v["params"]["keys"][0], "NPM_TOKEN");
        assert_eq!(v["params"]["challenge"], "chal-1");
        assert!(desktop_only(&VaultEvent::AuthzRequest {
            request_id: uuid::Uuid::nil(),
            starter: String::new(),
            project_dir: String::new(),
            command: String::new(),
            keys: vec![],
            challenge: String::new(),
        }));
        assert!(!desktop_only(&VaultEvent::ItemChanged {
            item_id: uuid::Uuid::nil(),
            revision_date: "r".into(),
            kind: "login".into(),
            deleted: false,
        }));
    }
}
