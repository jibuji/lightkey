//! 审计锚点（issue #75）——平台安全存储实现（`lk-core::audit_anchor` trait）。
//!
//! ## 平台后端（keyring）
//!
//! - Windows：Credential Manager（wincred）
//! - macOS：Keychain
//! - Linux：secret-service（GNOME Keyring / KWallet）/ kernel keyring
//!   （keyring crate 默认平台后端；依赖桌面会话，可能不可用）
//!
//! **fail-open 降级**（验收标准）：平台 keychain 不可用 → 降级到
//! [`lk_core::audit_anchor::FileAnchorSidecar`]（数据目录 0600 侧写文件），
//! 并暴露「degraded」状态供上层发出「锚点不可用、防篡改能力减弱」警告；
//! **绝不阻断 vault 解锁**（锚点写入失败只记警告，不向调用方传播错误）。
//!
//! 锚点值只需链尾 ordinal + last_hmac（从日志文件直接读出，无需 K_audit），
//! 因此锁定态/解锁态都能写入。

use std::sync::Arc;

use lk_core::audit_anchor::{
    AuditAnchorStore, AuditAnchorValue, CompositeAuditAnchor, FileAnchorSidecar,
};

/// 审计锚点平台 store 的 keyring service 名（user = 固定标识）。
pub const AUDIT_ANCHOR_SERVICE: &str = "lightkey-audit-anchor";
/// keyring `Entry` 的 user 标识（单库单锚点）。
const AUDIT_ANCHOR_USER: &str = "chain-tail";

/// keyring 平台锚点（Windows CM / macOS Keychain / Linux secret-service·keyutils）。
///
/// 所有方法都**无 panic**：`Entry::new` 与 get/set 失败统一映射为
/// [`lk_core::audit_anchor::AuditAnchorError::Unavailable`]，由组合锚点 fail-open。
#[derive(Debug)]
pub struct KeyringAuditAnchor;

impl AuditAnchorStore for KeyringAuditAnchor {
    fn name(&self) -> &'static str {
        "keyring"
    }

    fn read(
        &self,
    ) -> std::result::Result<Option<AuditAnchorValue>, lk_core::audit_anchor::AuditAnchorError>
    {
        let entry = match keyring::Entry::new(AUDIT_ANCHOR_SERVICE, AUDIT_ANCHOR_USER) {
            Ok(e) => e,
            Err(e) => {
                return Err(lk_core::audit_anchor::AuditAnchorError::Unavailable(
                    e.to_string(),
                ))
            }
        };
        match entry.get_password() {
            Ok(s) => serde_json::from_str(&s)
                .map(Some)
                .map_err(|e| lk_core::audit_anchor::AuditAnchorError::Io(e.to_string())),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(lk_core::audit_anchor::AuditAnchorError::Unavailable(
                e.to_string(),
            )),
        }
    }

    fn write(
        &self,
        value: &AuditAnchorValue,
    ) -> std::result::Result<(), lk_core::audit_anchor::AuditAnchorError> {
        let entry = match keyring::Entry::new(AUDIT_ANCHOR_SERVICE, AUDIT_ANCHOR_USER) {
            Ok(e) => e,
            Err(e) => {
                return Err(lk_core::audit_anchor::AuditAnchorError::Unavailable(
                    e.to_string(),
                ))
            }
        };
        let s = serde_json::to_string(value)
            .map_err(|e| lk_core::audit_anchor::AuditAnchorError::Io(e.to_string()))?;
        entry
            .set_password(&s)
            .map_err(|e| lk_core::audit_anchor::AuditAnchorError::Unavailable(e.to_string()))
    }
}

/// 装配审计锚点：平台 keyring + 侧写降级，包装为 `Arc`（守护进程命令线程 /
/// 后台 flush 线程跨线程共享）。
pub fn make_audit_anchor(dir: &std::path::Path) -> Arc<CompositeAuditAnchor> {
    Arc::new(CompositeAuditAnchor::new(
        Some(Box::new(KeyringAuditAnchor)),
        FileAnchorSidecar::new(dir),
    ))
}
