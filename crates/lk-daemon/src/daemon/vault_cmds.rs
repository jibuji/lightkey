//! vault.* / 锁定 / 会话令牌 / 关停

use super::*;
use crate::transport;

impl Daemon {
    pub(crate) fn vault_status(&self, id: Value) -> RpcResponse {
        let unlocked = self.vault_peek();
        let initialized = vault::vault_exists(&self.shared.dir);
        let watermark = self.shared.sync.lock().unwrap().state.watermark.clone();
        let result = StatusResult {
            unlocked,
            initialized,
            version: env!("CARGO_PKG_VERSION").to_string(),
            sync_watermark: watermark,
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    pub(crate) fn vault_init(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: InitParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // 重置会清空当前解锁态 + 重写全部密文：写锁排除同步应用阶段
        // （避免与文件重写竞态；锁只保护数据层内存一致性）
        let result = if p.force {
            let shared = Arc::clone(&self.shared);
            let mut vault_guard = shared.vault.write().unwrap();
            self.lock_internal_locked(&mut vault_guard, LockReason::Manual);
            let r = vault::init_vault(&shared.dir, &p.master_password, true, &mut self.audit);
            drop(vault_guard);
            r
        } else {
            vault::init_vault(&self.shared.dir, &p.master_password, false, &mut self.audit)
        };
        match result {
            Ok((_header, code)) => {
                let result = InitResult {
                    recovery_code: code.display(),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(Error::VaultExists) => {
                RpcResponse::err(id, ERR_VAULT_EXISTS, MSG_VAULT_EXISTS, None)
            }
            Err(Error::WeakPassword) => {
                RpcResponse::err(id, ERR_WEAK_PASSWORD, MSG_WEAK_PASSWORD, None)
            }
            Err(e) => RpcResponse::err(
                id,
                ERR_VAULT_INVALID,
                MSG_VAULT_INVALID,
                Some(json!({ "detail": e.to_string() })),
            ),
        }
    }

    pub(crate) fn vault_unlock(&mut self, id: Value, params: Value) -> RpcResponse {
        // 限流（失败计数 + 退避）
        if let Some(retry) = self.unlock_guard.check() {
            return RpcResponse::err(
                id,
                ERR_RATE_LIMITED,
                MSG_RATE_LIMITED,
                Some(json!({ "retryAfterSeconds": retry })),
            );
        }
        let p: UnlockParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let unlocked = UnlockedVault::unlock(&self.shared.dir, &p.master_password);
        match unlocked {
            Ok(mut vault) => {
                // 过期墓碑清理（30 天延迟硬删）。同步已配置时跳过：硬删
                // 需「≥30 天且已同步确认」，由同步引擎裁决（sync.md §4）。
                if self.shared.config.read().unwrap().sync.is_none() {
                    let _ = vault.purge_expired(&lk_core::crypto::now_iso());
                }
                self.unlock_guard.on_success();
                let _ = self.audit.append(
                    vault.keys(),
                    &EventInput::new("lk", "vault.unlock", AuditResult::Allowed),
                );
                // C 层装配：vault-store 挂总线（写成功 → `item.changed`）
                self.core.attach_vault(&mut vault);
                *self.shared.vault.write().unwrap() = Some(vault);
                let token = self.sessions.issue();
                self.write_session_token(&token);
                let result = UnlockResult {
                    token: hex::encode(token),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(_) => {
                // 统一文案：主密码错误 / 库未初始化（防探测）
                self.unlock_guard.on_failure();
                RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None)
            }
        }
    }

    pub(crate) fn vault_lock(&mut self, id: Value) -> RpcResponse {
        self.lock_internal();
        // 空对象而非 null：避免客户端把 result:null 解析为「无 result」
        RpcResponse::ok(id, json!({}))
    }

    /// 锁定：先签名审计事件（用当前 K_audit），再擦除密钥 + 失效令牌 + 删令牌文件。
    /// 默认 reason = manual（`lock_internal_with` 可指定）。
    pub(crate) fn lock_internal(&mut self) {
        self.lock_internal_with(LockReason::Manual);
    }

    /// 锁定（`reason` 进 `session.locked` 事件负载）。
    pub(crate) fn lock_internal_with(&mut self, reason: LockReason) {
        let shared = Arc::clone(&self.shared);
        let mut vault = shared.vault.write().unwrap();
        self.lock_internal_locked(&mut vault, reason);
    }

    /// 带原因的锁定（M2 desktop：锁屏自动锁定 `LockReason::Lockscreen`）。
    ///
    /// 桌面壳在进程内直接调用（不经 IPC，避免引入协议面）：锁屏检测线程
    /// → `lock_with_reason(Lockscreen)` → 事件总线广播 `session.locked`
    /// （reason=lockscreen）→ 通知桥推送给订阅中的前端。
    pub fn lock_with_reason(&mut self, reason: LockReason) {
        self.lock_internal_with(reason);
    }

    /// 锁定（调用方已持 vault 写锁；供锁定/恢复/强制重置共用）。
    pub(crate) fn lock_internal_locked(
        &mut self,
        vault: &mut Option<UnlockedVault>,
        reason: LockReason,
    ) {
        if let Some(v) = vault {
            let _ = self.audit.append(
                v.keys(),
                &EventInput::new("lk", "vault.lock", AuditResult::Allowed),
            );
        }
        *vault = None;
        self.sessions.invalidate_with(reason);
        self.remove_session_token();
    }

    pub(crate) fn vault_recover(&mut self, id: Value, params: Value) -> RpcResponse {
        // 限流（失败计数 + 指数退避，与 vault.unlock 对称；A4）
        if let Some(retry) = self.recover_guard.check() {
            return RpcResponse::err(
                id,
                ERR_RATE_LIMITED,
                MSG_RATE_LIMITED,
                Some(json!({ "retryAfterSeconds": retry })),
            );
        }
        let p: RecoverParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // 恢复会更换全部密钥并重写全部密文：写锁排除同步应用阶段
        let shared = Arc::clone(&self.shared);
        let mut vault_guard = shared.vault.write().unwrap();
        // 恢复会更换全部密钥：现有解锁态（旧钥）立即作废
        self.lock_internal_locked(&mut vault_guard, LockReason::Manual);
        let code = match RecoveryCode::parse(&p.recovery_code) {
            Ok(c) => c,
            Err(_) => {
                self.recover_guard.on_failure();
                return RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None);
            }
        };
        match vault::recover_vault(&shared.dir, &code, &p.new_password, &mut self.audit) {
            Ok(new_code) => {
                self.recover_guard.on_success();
                let result = RecoverResult {
                    recovery_code: new_code.display(),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(Error::WeakPassword) => {
                // 新主密码不满足最小长度（与 vault.init 同策略）
                self.recover_guard.on_failure();
                RpcResponse::err(id, ERR_WEAK_PASSWORD, MSG_WEAK_PASSWORD, None)
            }
            Err(_) => {
                // 统一：恢复码错误 / 信封损坏 / 未初始化
                self.recover_guard.on_failure();
                RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None)
            }
        }
    }

    pub(crate) fn auto_lock_if_idle(&mut self) {
        let idle = self.shared.config.read().unwrap().auto_lock_minutes;
        let elapsed = self.last_activity.elapsed();
        let timeout = Duration::from_secs(idle * 60);
        if self.vault_peek() && elapsed >= timeout {
            self.lock_internal_with(LockReason::Timeout);
        }
    }

    pub(crate) fn session_token_path(&self) -> std::path::PathBuf {
        self.shared.dir.join(SESSION_TOKEN_FILE)
    }

    pub(crate) fn write_session_token(&self, token: &[u8; 32]) {
        let path = self.session_token_path();
        // 取舍说明（A1）：CLI 每次调用是独立进程，令牌须经进程间传递才能
        // 跨命令复用解锁态；ipc.md §3「令牌不落盘」以桌面/浏览器进程常驻为
        // 前提，CLI 落地方式与规格字面冲突（文档修订另走 docs 同步）。
        // 风险面收窄到同用户：文件 0600 + 用户私有目录 + 锁定/退出即删除。
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            let _ = std::io::Write::write_all(&mut f, hex::encode(token).as_bytes());
        }
    }

    pub(crate) fn remove_session_token(&self) {
        let _ = std::fs::remove_file(self.session_token_path());
    }

    /// 退出清理：删令牌 + 删端点文件（socket 由 OS 回收）。
    pub fn shutdown(&mut self) {
        let saved = { self.shared.sync.lock().unwrap().clone() };
        saved.save(&self.shared.dir);
        // 广播 `session.locked(daemon-exit)`（进程退出前的最后事件）
        self.sessions.invalidate_with(LockReason::DaemonExit);
        self.remove_session_token();
        if let Some(ep) = transport::read_endpoint(&self.shared.dir) {
            transport::cleanup(&self.shared.dir, &ep);
        }
    }
}
