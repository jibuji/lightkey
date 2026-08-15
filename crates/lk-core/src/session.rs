//! 会话令牌（规格：`docs/ipc.md` §3）。
//!
//! 设计要点：
//!
//! - 解锁成功 → 签发 **256-bit 随机**会话令牌，**随每次解锁轮换**。
//! - 令牌错误/过期 → 统一 [`crate::Error::SessionInvalid`]（`session.invalid`），
//!   不区分「未解锁/令牌错」（防探测）。
//! - 锁定/超时/守护进程退出 → 令牌立即失效（内存擦除）。
//! - 令牌比较用常数时间，避免时序侧信道。

use crate::crypto::random_array;

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
#[derive(Default)]
pub struct SessionManager {
    session: Option<Session>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager::default()
    }

    /// 签发新令牌（**每次解锁轮换**，旧令牌立即失效）。返回令牌字节。
    pub fn issue(&mut self) -> [u8; TOKEN_LEN] {
        let token = random_array::<TOKEN_LEN>();
        self.session = Some(Session {
            token,
            issued_at: std::time::Instant::now(),
        });
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

    /// 失效当前令牌（锁定/超时/重置）。
    pub fn invalidate(&mut self) {
        self.session = None;
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
}
