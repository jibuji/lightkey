//! 事件总线（A/B 层解耦；契约见 `docs/plugin-architecture.md` §5）。
//!
//! 用 trait 事件 + 分发器**模拟** Cordis `emit` 语义（不移植 Cordis）：
//!
//! - [`EventBus::emit`] = 观察广播（fire-and-forget）：无返回值、互不阻塞，
//!   订阅者之间不依赖顺序与结果；分发顺序 = 订阅顺序。
//! - 订阅者（[`EventSink`]）必须是**非阻塞**的：不得反向获取守护进程锁、
//!   不得在回调内做网络 I/O（与 Cordis `emit` 的观察者约定一致）。
//! - 单个订阅者失败（panic）不影响发送者与其他订阅者（逐个捕获）。
//!
//! ## 事件清单（§5.2，负载最小字段、**无密钥值**）
//!
//! | 事件 | 负载 | 发送方（插件边界） | 监听者 |
//! |------|------|--------------------|--------|
//! | [`VaultEvent::ItemChanged`] | `{ itemId, revisionDate, kind, deleted }`（`kind` = 协议字段 `type`，`type` 为 Rust 关键字故用 `kind`；M2 IPC 通知桥序列化时映射回 `type`） | vault-store（A） | sync-engine（B）· audit（A）· ui-vault（D） |
//! | [`VaultEvent::SessionUnlocked`] | `{ via }` | session（A） | ui 各插件（D）· sync-engine（B） |
//! | [`VaultEvent::SessionLocked`] | `{ reason }` | session（A） | ui 各插件（D）· sync-engine（B） |
//!
//! `authz.request` 留待 M2 随 authz-gate 接入（D 层 TS 侧事件契约已含，
//! 见 `frontend/src/events.ts`）。
//!
//! 跨进程方向（§5.3）：Rust 事件 → IPC 通知 → TS 侧重新 `emit`；M1.5 的
//! IPC 协议零变更（`docs/ipc.md` 不变），Rust 事件在守护进程内广播，
//! 由测试与未来 M2 的 IPC 通知桥消费。TS 侧事件（`theme.changed` /
//! `clipboard.copied`）不跨进程，纯 D 层内部广播。

use std::sync::{Arc, Mutex};

/// 解锁方式（`session.unlocked.via`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionVia {
    Password,
    Biometric,
    Recovery,
}

impl SessionVia {
    /// 协议面字符串（`docs/plugin-architecture.md` §5.2）。
    pub fn as_str(self) -> &'static str {
        match self {
            SessionVia::Password => "password",
            SessionVia::Biometric => "biometric",
            SessionVia::Recovery => "recovery",
        }
    }
}

/// 锁定原因（`session.locked.reason`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Manual,
    Timeout,
    Lockscreen,
    DaemonExit,
}

impl LockReason {
    /// 协议面字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            LockReason::Manual => "manual",
            LockReason::Timeout => "timeout",
            LockReason::Lockscreen => "lockscreen",
            LockReason::DaemonExit => "daemon-exit",
        }
    }
}

/// 总线事件（Rust A/B 层；负载只含索引级元数据，**永不含密钥值**）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultEvent {
    /// `item.changed`：条目新建/更新（`deleted=false`）或软删除（`deleted=true`）。
    /// M2 起规则变更同样广播本事件（`kind="rule"`，决策 #6）。
    ItemChanged {
        item_id: uuid::Uuid,
        revision_date: String,
        /// 对象类型（login/note/secret/file/rule）；协议字段为 `type`
        /// （`type` 是 Rust 关键字，故内部用 `kind`）。
        kind: String,
        deleted: bool,
    },
    /// `session.unlocked`：解锁成功（令牌已轮换）。
    SessionUnlocked { via: SessionVia },
    /// `session.locked`：锁定（令牌已失效、密钥已擦除）。
    SessionLocked { reason: LockReason },
    /// `authz.request`（M2）：授权门进入第 3 层弹窗审批——「需要用户决策」
    /// 的通知（plugin-architecture.md §5.3）；决策权始终在 Rust 侧，
    /// 用户选择经 `approval.result` 回传。`keys` 仅 key 名，永不含值。
    /// `challenge` 为一次性审批应答值（#78 方案 B）：随本事件仅投递给
    /// 桌面订阅者，回传时必须原样带回（ipc.md §4 / authorization-gate.md §6）。
    AuthzRequest {
        request_id: uuid::Uuid,
        starter: String,
        project_dir: String,
        command: String,
        keys: Vec<String>,
        challenge: String,
    },
}

impl VaultEvent {
    /// 事件名（与 `docs/plugin-architecture.md` §5.2 契约一致）。
    pub fn name(&self) -> &'static str {
        match self {
            VaultEvent::ItemChanged { .. } => "item.changed",
            VaultEvent::SessionUnlocked { .. } => "session.unlocked",
            VaultEvent::SessionLocked { .. } => "session.locked",
            VaultEvent::AuthzRequest { .. } => "authz.request",
        }
    }
}

/// 事件订阅者（Cordis `on` 的 Rust 模拟）。
///
/// 约束：回调必须**非阻塞**（不得获取守护进程锁 / 网络 I/O）；异常由总线
/// 捕获，不影响发送者与其他订阅者。
pub trait EventSink: Send + Sync {
    fn on_event(&self, event: &VaultEvent);
}

/// 闭包订阅者（测试与宿主装配的便捷形态）。
pub struct FnSink<F>(F)
where
    F: Fn(&VaultEvent) + Send + Sync;

impl<F> FnSink<F>
where
    F: Fn(&VaultEvent) + Send + Sync,
{
    pub fn new(f: F) -> FnSink<F> {
        FnSink(f)
    }
}

impl<F> EventSink for FnSink<F>
where
    F: Fn(&VaultEvent) + Send + Sync,
{
    fn on_event(&self, event: &VaultEvent) {
        (self.0)(event)
    }
}

/// 事件总线（默认空；`subscribe` 可重复调用，重复注册 = 重复回调）。
///
/// `emit` 语义与 Cordis 一致：同步、按订阅顺序、fire-and-forget。
#[derive(Default)]
pub struct EventBus {
    sinks: Mutex<Vec<Arc<dyn EventSink>>>,
}

impl EventBus {
    pub fn new() -> EventBus {
        EventBus::default()
    }

    /// 订阅（返回订阅者自身的 Arc；生命周期随调用方持有，不自动退订）。
    pub fn subscribe(&self, sink: Arc<dyn EventSink>) {
        self.sinks.lock().unwrap().push(sink);
    }

    /// 订阅者数量（测试断言用）。
    pub fn subscriber_count(&self) -> usize {
        self.sinks.lock().unwrap().len()
    }

    /// 广播事件：按订阅顺序逐个调用；单个订阅者 panic 被捕获，不影响
    /// 发送者与其他订阅者（fire-and-forget，观察广播）。
    pub fn emit(&self, event: &VaultEvent) {
        let sinks: Vec<Arc<dyn EventSink>> = self.sinks.lock().unwrap().clone();
        for sink in sinks {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink.on_event(event);
            }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emit_fanout_in_subscription_order() {
        let bus = EventBus::new();
        let order = Arc::new(Mutex::new(Vec::new()));
        let o1 = Arc::clone(&order);
        bus.subscribe(Arc::new(FnSink::new(move |_| {
            o1.lock().unwrap().push(1);
        })));
        let o2 = Arc::clone(&order);
        bus.subscribe(Arc::new(FnSink::new(move |_| {
            o2.lock().unwrap().push(2);
        })));
        bus.emit(&VaultEvent::SessionUnlocked {
            via: SessionVia::Password,
        });
        assert_eq!(*order.lock().unwrap(), vec![1, 2]);
    }

    #[test]
    fn emit_is_fire_and_forget_no_return_value() {
        // emit 返回 ()：观察广播无聚合结果（契约 §5.1）
        let bus = EventBus::new();
        let hit = Arc::new(Mutex::new(0));
        let h = Arc::clone(&hit);
        bus.subscribe(Arc::new(FnSink::new(move |e| {
            assert_eq!(e.name(), "item.changed");
            *h.lock().unwrap() += 1;
        })));
        bus.emit(&VaultEvent::ItemChanged {
            item_id: uuid::Uuid::nil(),
            revision_date: "r".into(),
            kind: "login".into(),
            deleted: false,
        });
        assert_eq!(*hit.lock().unwrap(), 1);
    }

    #[test]
    fn panicking_sink_does_not_break_others() {
        let bus = EventBus::new();
        bus.subscribe(Arc::new(FnSink::new(|_| panic!("sink bug"))));
        let hit = Arc::new(Mutex::new(0));
        let h = Arc::clone(&hit);
        bus.subscribe(Arc::new(FnSink::new(move |_| {
            *h.lock().unwrap() += 1;
        })));
        bus.emit(&VaultEvent::SessionLocked {
            reason: LockReason::Manual,
        });
        assert_eq!(*hit.lock().unwrap(), 1);
    }

    #[test]
    fn event_names_and_payload_strings_match_contract() {
        assert_eq!(
            VaultEvent::ItemChanged {
                item_id: uuid::Uuid::nil(),
                revision_date: "r".into(),
                kind: "login".into(),
                deleted: false,
            }
            .name(),
            "item.changed"
        );
        assert_eq!(SessionVia::Password.as_str(), "password");
        assert_eq!(SessionVia::Biometric.as_str(), "biometric");
        assert_eq!(SessionVia::Recovery.as_str(), "recovery");
        assert_eq!(LockReason::Manual.as_str(), "manual");
        assert_eq!(LockReason::Timeout.as_str(), "timeout");
        assert_eq!(LockReason::Lockscreen.as_str(), "lockscreen");
        assert_eq!(LockReason::DaemonExit.as_str(), "daemon-exit");
        assert_eq!(
            VaultEvent::AuthzRequest {
                request_id: uuid::Uuid::nil(),
                starter: "s".into(),
                project_dir: "/p".into(),
                command: "npm publish".into(),
                keys: vec!["NPM_TOKEN".into()],
                challenge: "chal".into(),
            }
            .name(),
            "authz.request"
        );
    }
}
