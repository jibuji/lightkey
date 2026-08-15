//! 守护进程状态机与请求分发（规格：`docs/ipc.md`、`docs/audit.md`）。
//!
//! - 持解锁态：密钥只存在于守护进程内存（`UnlockedVault`），锁定即擦除。
//! - 会话令牌随每次解锁轮换（`session.token` 文件 0600 供 CLI 进程间传递，
//!   锁定即删除）；令牌错误/过期 → 统一 `session.invalid`（防探测）。
//! - `vault.unlock` 失败计数 + 指数退避（防暴力）。
//! - 空闲超时自动锁定（默认 5 分钟，`config.json` 可配；0 = 下次请求即锁）。
//! - 审计：守护进程是唯一写入方；未解锁态无法派生 K_audit → 失败解锁不落
//!   审计（限流兜底），解锁成功与之后的一切敏感操作签名留痕。

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use base64::Engine as _;
use lk_core::audit::{AuditLog, AuditResult, EventInput};
use lk_core::ipc::*;
use lk_core::recovery::RecoveryCode;
use lk_core::session::SessionManager;
use lk_core::vault::{self, UnlockedVault};
use lk_core::Error;
use serde_json::{json, Value};

/// 会话令牌文件名（0600；CLI 进程间传递，锁定即删除）。
pub const SESSION_TOKEN_FILE: &str = "session.token";
/// 配置文件名。
pub const CONFIG_FILE: &str = "config.json";

/// 守护进程配置（`config.json`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// 空闲自动锁定分钟数（0 = 下次请求即锁；默认 5）。
    pub auto_lock_minutes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            auto_lock_minutes: 5,
        }
    }
}

/// `vault.unlock` 限流：失败计数 + 指数退避（5 次后 2^(n-5) 秒，封顶 300s）。
#[derive(Debug, Default)]
struct UnlockGuard {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl UnlockGuard {
    fn retry_after(&self) -> Option<u64> {
        self.blocked_until
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .map(|d| d.as_secs())
    }

    fn check(&self) -> Option<u64> {
        self.retry_after()
    }

    fn on_failure(&mut self) {
        self.failures += 1;
        if self.failures >= 5 {
            let backoff = 2u64.saturating_pow(self.failures - 5).min(300);
            self.blocked_until = Some(Instant::now() + Duration::from_secs(backoff));
        }
    }

    fn on_success(&mut self) {
        self.failures = 0;
        self.blocked_until = None;
    }
}

/// 守护进程状态。
pub struct Daemon {
    dir: std::path::PathBuf,
    config: Config,
    vault: Option<UnlockedVault>,
    sessions: SessionManager,
    audit: AuditLog,
    unlock_guard: UnlockGuard,
    last_activity: Instant,
}

/// 信号处理标志（unix：SIGINT/SIGTERM 优雅退出）。
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

impl Daemon {
    /// 启动（绑定端点、加载配置、装信号处理）。
    pub fn start(dir: &Path) -> Result<Daemon, String> {
        let dir = dir.to_path_buf();
        let audit = AuditLog::open(&dir).map_err(|e| e.to_string())?;
        let config = load_config(&dir);
        install_shutdown_handlers();
        Ok(Daemon {
            dir,
            config,
            vault: None,
            sessions: SessionManager::new(),
            audit,
            unlock_guard: UnlockGuard::default(),
            last_activity: Instant::now(),
        })
    }

    /// 处理一行 JSON-RPC 请求，返回一行响应（永不 panic）。
    pub fn handle(&mut self, line: &str) -> String {
        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => {
                return serde_json::to_string(&RpcResponse::err(
                    Value::Null,
                    ERR_PARSE,
                    "parse error",
                    None,
                ))
                .unwrap_or_else(|_| "{}".into());
            }
        };
        self.dispatch(req)
    }

    fn dispatch(&mut self, req: RpcRequest) -> String {
        let id = req.id.clone();
        let method = req.method.clone();
        let params = req.params;
        let token = extract_token(&params);

        // 空闲超时自动锁定（任何请求都会触发检查）
        self.auto_lock_if_idle();

        let resp = match method.as_str() {
            M_VAULT_STATUS => self.vault_status(id.clone()),
            M_VAULT_INIT => self.vault_init(id.clone(), params),
            M_VAULT_UNLOCK => self.vault_unlock(id.clone(), params),
            M_VAULT_LOCK => self.vault_lock(id.clone()),
            M_VAULT_RECOVER => self.vault_recover(id.clone(), params),
            M_ITEM_LIST => self.require_session(id.clone(), token, |me| me.item_list(id.clone())),
            M_ITEM_GET => {
                self.require_session(id.clone(), token, |me| me.item_get(id.clone(), params))
            }
            M_ITEM_PUT => {
                self.require_session(id.clone(), token, |me| me.item_put(id.clone(), params))
            }
            M_ITEM_DELETE => {
                self.require_session(id.clone(), token, |me| me.item_delete(id.clone(), params))
            }
            M_ITEM_EXPORT => {
                self.require_session(id.clone(), token, |me| me.item_export(id.clone(), params))
            }
            M_AUDIT_LIST => {
                self.require_session(id.clone(), token, |me| me.audit_list(id.clone(), params))
            }
            M_AUDIT_VERIFY => {
                self.require_session(id.clone(), token, |me| me.audit_verify(id.clone()))
            }
            // M1/M2 占位
            M_SYNC_TRIGGER | M_SYNC_POLL | M_AUTHZ_EVALUATE | M_APPROVAL_REQUEST => {
                RpcResponse::err(id.clone(), ERR_METHOD_NOT_FOUND, MSG_METHOD_NOT_FOUND, None)
            }
            _ => RpcResponse::err(id.clone(), ERR_METHOD_NOT_FOUND, MSG_METHOD_NOT_FOUND, None),
        };
        self.last_activity = Instant::now();
        serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
    }

    // -- 会话 / 生命周期 ------------------------------------------------

    /// 需要有效会话的方法统一走这里：令牌错误/过期/未解锁 → `session.invalid`。
    fn require_session(
        &mut self,
        id: Value,
        token: Option<Vec<u8>>,
        f: impl FnOnce(&mut Self) -> RpcResponse,
    ) -> RpcResponse {
        if self.vault.is_some() && self.sessions.validate(token.as_deref().unwrap_or(&[])) {
            f(self)
        } else {
            session_invalid(id)
        }
    }

    fn vault_status(&self, id: Value) -> RpcResponse {
        let result = StatusResult {
            unlocked: self.vault.is_some(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            sync_watermark: None,
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    fn vault_init(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: InitParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // 重置会清空当前解锁态（若强制重置）
        if p.force {
            self.lock_internal();
        }
        match vault::init_vault(&self.dir, &p.master_password, p.force, &mut self.audit) {
            Ok((_header, code)) => {
                let result = InitResult {
                    recovery_code: code.display(),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(Error::VaultExists) => {
                RpcResponse::err(id, ERR_VAULT_EXISTS, MSG_VAULT_EXISTS, None)
            }
            Err(e) => RpcResponse::err(
                id,
                ERR_VAULT_INVALID,
                MSG_VAULT_INVALID,
                Some(json!({ "detail": e.to_string() })),
            ),
        }
    }

    fn vault_unlock(&mut self, id: Value, params: Value) -> RpcResponse {
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
        let unlocked = UnlockedVault::unlock(&self.dir, &p.master_password);
        match unlocked {
            Ok(mut vault) => {
                // 过期墓碑清理（30 天延迟硬删）
                let _ = vault.purge_expired(&lk_core::crypto::now_iso());
                self.unlock_guard.on_success();
                self.vault = Some(vault);
                let token = self.sessions.issue();
                self.write_session_token(&token);
                let _ = self.audit.append(
                    self.vault.as_ref().unwrap().keys(),
                    &EventInput::new("lk", "vault.unlock", AuditResult::Allowed),
                );
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

    fn vault_lock(&mut self, id: Value) -> RpcResponse {
        self.lock_internal();
        // 空对象而非 null：避免客户端把 result:null 解析为「无 result」
        RpcResponse::ok(id, json!({}))
    }

    /// 锁定：先签名审计事件（用当前 K_audit），再擦除密钥 + 失效令牌 + 删令牌文件。
    fn lock_internal(&mut self) {
        if let Some(vault) = &self.vault {
            let _ = self.audit.append(
                vault.keys(),
                &EventInput::new("lk", "vault.lock", AuditResult::Allowed),
            );
        }
        self.vault = None;
        self.sessions.invalidate();
        self.remove_session_token();
    }

    fn vault_recover(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: RecoverParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // 恢复会更换全部密钥：现有解锁态（旧钥）立即作废
        self.lock_internal();
        let code = match RecoveryCode::parse(&p.recovery_code) {
            Ok(c) => c,
            Err(_) => return RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None),
        };
        match vault::recover_vault(&self.dir, &code, &p.new_password, &mut self.audit) {
            Ok(new_code) => {
                let result = RecoverResult {
                    recovery_code: new_code.display(),
                };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(_) => {
                // 统一：恢复码错误 / 信封损坏 / 未初始化
                RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None)
            }
        }
    }

    fn auto_lock_if_idle(&mut self) {
        let idle = self.config.auto_lock_minutes;
        let elapsed = self.last_activity.elapsed();
        let timeout = Duration::from_secs(idle * 60);
        if self.vault.is_some() && elapsed >= timeout {
            self.lock_internal();
        }
    }

    fn session_token_path(&self) -> std::path::PathBuf {
        self.dir.join(SESSION_TOKEN_FILE)
    }

    fn write_session_token(&self, token: &[u8; 32]) {
        let path = self.session_token_path();
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

    fn remove_session_token(&self) {
        let _ = std::fs::remove_file(self.session_token_path());
    }

    /// 退出清理：删令牌 + 删端点文件（socket 由 OS 回收）。
    pub fn shutdown(&mut self) {
        self.remove_session_token();
        if let Some(ep) = super::transport::read_endpoint(&self.dir) {
            super::transport::cleanup(&self.dir, &ep);
        }
    }

    // -- 条目 / 审计 -----------------------------------------------------

    fn item_list(&mut self, id: Value) -> RpcResponse {
        let me = self.vault.as_mut().unwrap();
        match me.list() {
            Ok(items) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput::new("lk", "item.list", AuditResult::Allowed),
                );
                let result = ItemListResult { items };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    fn item_get(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ItemGetParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let me = self.vault.as_mut().unwrap();
        match me.get(p.id) {
            Ok(item) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput::new("lk", &format!("item.get {}", p.id), AuditResult::Allowed),
                );
                RpcResponse::ok(id, serde_json::to_value(item).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    fn item_put(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ItemPutParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let kind = p.item.kind().as_str();
        let me = self.vault.as_mut().unwrap();
        match me.put(p.id, p.item, p.expected_revision) {
            Ok(item) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput::new(
                        "lk",
                        &format!("item.put {} <redacted>", kind),
                        AuditResult::Allowed,
                    ),
                );
                let result = ItemPutResult { item };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    fn item_delete(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ItemDeleteParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let me = self.vault.as_mut().unwrap();
        match me.delete(p.id) {
            Ok(_tomb) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput::new("lk", &format!("item.delete {}", p.id), AuditResult::Allowed),
                );
                RpcResponse::ok(id, json!({}))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    fn item_export(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ItemExportParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let me = self.vault.as_mut().unwrap();
        match me.export(p.id) {
            Ok(bundle) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput::new("lk", &format!("item.export {}", p.id), AuditResult::Allowed),
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

    fn audit_list(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: AuditListParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let me = self.vault.as_mut().unwrap();
        let events = self.audit.read();
        let _ = self.audit.append(
            me.keys(),
            &EventInput::new("lk", "audit.list", AuditResult::Allowed),
        );
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

    fn audit_verify(&mut self, id: Value) -> RpcResponse {
        let me = self.vault.as_mut().unwrap();
        let keys = me.keys();
        // 仅当前密钥可验证的部分（轮换点前事件需旧钥，M0 如实报告）
        match self.audit.verify(keys, &|_| None) {
            Ok(verified) => {
                let result = AuditVerifyResult { verified };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => RpcResponse::err(
                id,
                ERR_AUDIT_VERIFY,
                MSG_AUDIT_VERIFY,
                Some(json!({ "detail": e.to_string() })),
            ),
        }
    }

    fn err_response(&self, id: Value, e: &Error) -> RpcResponse {
        match e {
            Error::Conflict => RpcResponse::err(id, ERR_ITEM_CONFLICT, MSG_ITEM_CONFLICT, None),
            Error::ItemNotFound(id0) => RpcResponse::err(
                id,
                ERR_ITEM_NOT_FOUND,
                MSG_ITEM_NOT_FOUND,
                Some(json!({ "id": id0.to_string() })),
            ),
            Error::Limit(msg) => {
                RpcResponse::err(id, ERR_LIMIT, MSG_LIMIT, Some(json!({ "detail": msg })))
            }
            _ => RpcResponse::err(
                id,
                ERR_VAULT_INVALID,
                MSG_VAULT_INVALID,
                Some(json!({ "detail": e.to_string() })),
            ),
        }
    }
}

fn extract_token(params: &Value) -> Option<Vec<u8>> {
    params
        .get("token")
        .and_then(|t| t.as_str())
        .and_then(|s| hex::decode(s.trim()).ok())
}

fn load_config(dir: &Path) -> Config {
    let path = dir.join(CONFIG_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<Config>(&bytes).unwrap_or_default(),
        Err(_) => {
            let cfg = Config::default();
            let _ = std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap_or_default());
            cfg
        }
    }
}

#[cfg(unix)]
fn install_shutdown_handlers() {
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        );
    }
}

#[cfg(windows)]
fn install_shutdown_handlers() {
    // Windows 控制台 Ctrl+C：进程默认终止；令牌文件残留由下次启动覆盖。
}

#[cfg(unix)]
extern "C" fn handle_signal(_: libc::c_int) {
    SHUTDOWN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// 全局信号标志的引用（供 transport 主循环轮询）。
pub fn global_shutdown() -> &'static AtomicBool {
    &SHUTDOWN
}
