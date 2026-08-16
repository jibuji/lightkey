//! 会话令牌（规格：`docs/ipc.md` §3）。
//!
//! 设计要点：
//!
//! - 解锁成功 → 签发 **256-bit 随机**会话令牌，**随每次解锁轮换**。
//! - 令牌错误/过期 → 统一 [`crate::Error::SessionInvalid`]（`session.invalid`），
//!   不区分「未解锁/令牌错」（防探测）。
//! - 锁定/超时/守护进程退出 → 令牌立即失效（内存擦除）。
//! - 令牌比较用常数时间，避免时序侧信道。

use crate::bus::{EventBus, LockReason, SessionVia, VaultEvent};
use crate::crypto::random_array;
use std::sync::Arc;

/// 会话令牌长度（256-bit = 32B）。
pub const TOKEN_LEN: usize = 32;

/// 常数时间比较（防时序侧信道）。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 解锁会话（令牌 + 签发时间）。
struct Session {
    token: [u8; TOKEN_LEN],
    issued_at: std::time::Instant,
}

/// 会话管理器：签发/校验/轮换/失效。密钥与令牌只存在于守护进程内存。
///
/// 可选事件总线（A 层插件边界，`docs/plugin-architecture.md` §3.1）：
/// 签发 → `session.unlocked`、失效 → `session.locked`（fire-and-forget
/// 观察广播；未挂总线 = 零行为差异）。
#[derive(Default)]
pub struct SessionManager {
    session: Option<Session>,
    bus: Option<Arc<EventBus>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager::default()
    }

    /// 挂载事件总线（C 层宿主装配；缺省 = 不广播）。
    pub fn attach_bus(&mut self, bus: Arc<EventBus>) {
        self.bus = Some(bus);
    }

    /// 签发新令牌（**每次解锁轮换**，旧令牌立即失效）。返回令牌字节。
    /// 默认视为密码解锁（`issue_with` 可指定解锁方式）。
    pub fn issue(&mut self) -> [u8; TOKEN_LEN] {
        self.issue_with(SessionVia::Password)
    }

    /// 签发新令牌（指定解锁方式；`session.unlocked` 负载的 `via`）。
    pub fn issue_with(&mut self, via: SessionVia) -> [u8; TOKEN_LEN] {
        let token = random_array::<TOKEN_LEN>();
        self.session = Some(Session {
            token,
            issued_at: std::time::Instant::now(),
        });
        if let Some(bus) = &self.bus {
            bus.emit(&VaultEvent::SessionUnlocked { via });
        }
        token
    }

    /// 校验令牌；错误/过期/未解锁 → false（统一，防探测）。
    pub fn validate(&self, token: &[u8]) -> bool {
        match &self.session {
            Some(s) => ct_eq(&s.token, token),
            None => false,
        }
    }

    /// 是否已解锁（有有效会话）。
    pub fn is_unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// 会话时长（供空闲超时判定）。
    pub fn elapsed(&self) -> Option<std::time::Duration> {
        self.session.as_ref().map(|s| s.issued_at.elapsed())
    }

    /// 失效当前令牌（锁定/超时/重置）。默认视为手动锁定
    /// （`invalidate_with` 可指定原因）。
    pub fn invalidate(&mut self) {
        self.invalidate_with(LockReason::Manual);
    }

    /// 失效当前令牌（指定原因；`session.locked` 负载的 `reason`）。
    pub fn invalidate_with(&mut self, reason: LockReason) {
        self.session = None;
        if let Some(bus) = &self.bus {
            bus.emit(&VaultEvent::SessionLocked { reason });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_validate_invalidate() {
        let mut m = SessionManager::new();
        assert!(!m.is_unlocked());
        assert!(!m.validate(&[0u8; TOKEN_LEN]));
        let t1 = m.issue();
        assert!(m.is_unlocked());
        assert!(m.validate(&t1));
        // 错误令牌 → false（统一）
        let mut wrong = t1;
        wrong[0] ^= 1;
        assert!(!m.validate(&wrong));
        // 截断/超长 → false
        assert!(!m.validate(&t1[..16]));
        // 锁定 → 全部失效
        m.invalidate();
        assert!(!m.is_unlocked());
        assert!(!m.validate(&t1));
    }

    #[test]
    fn reissue_rotates_token() {
        let mut m = SessionManager::new();
        let t1 = m.issue();
        let t2 = m.issue();
        assert_ne!(t1, t2, "每次解锁轮换令牌");
        assert!(!m.validate(&t1), "旧令牌立即失效");
        assert!(m.validate(&t2));
    }

    #[test]
    fn events_unlocked_locked() {
        use crate::bus::FnSink;
        use std::sync::{Arc, Mutex};

        let bus = Arc::new(EventBus::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        bus.subscribe(Arc::new(FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone())
        })));
        let mut m = SessionManager::new();
        m.attach_bus(bus);
        // 未挂总线前的语义保持：new() 默认不广播
        let mut silent = SessionManager::new();
        silent.issue();
        assert!(silent.is_unlocked());

        m.issue_with(SessionVia::Biometric);
        m.invalidate_with(LockReason::Timeout);
        m.issue_with(SessionVia::Recovery);
        m.invalidate_with(LockReason::Manual);
        let seen = events.lock().unwrap().clone();
        assert_eq!(seen.len(), 4);
        assert!(matches!(
            &seen[0],
            VaultEvent::SessionUnlocked {
                via: SessionVia::Biometric
            }
        ));
        assert!(matches!(
            &seen[1],
            VaultEvent::SessionLocked {
                reason: LockReason::Timeout
            }
        ));
        assert!(matches!(
            &seen[2],
            VaultEvent::SessionUnlocked {
                via: SessionVia::Recovery
            }
        ));
        assert!(matches!(
            &seen[3],
            VaultEvent::SessionLocked {
                reason: LockReason::Manual
            }
        ));
    }
}
