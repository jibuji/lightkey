//! 守护进程状态机与请求分发（规格：`docs/ipc.md`、`docs/audit.md`）。
//!
//! - 持解锁态：密钥只存在于守护进程内存（`UnlockedVault`），锁定即擦除。
//! - 会话令牌随每次解锁轮换（`session.token` 文件 0600 供 CLI 进程间传递，
//!   锁定即删除）；令牌错误/过期 → 统一 `session.invalid`（防探测）。
//! - `vault.unlock` / `vault.recover` 失败计数 + 指数退避（防暴力）。
//! - 空闲超时自动锁定（默认 5 分钟，`config.json` 可配；0 = 下次请求即锁）。
//! - 审计：守护进程是唯一写入方；未解锁态无法派生 K_audit → 失败解锁不落
//!   审计（限流兜底），解锁成功与之后的一切敏感操作签名留痕。
//! - M1 同步：`config.json` 的 `sync` 段（`lk config sync set` 写入）驱动
//!   后台轮询线程——只在解锁态轮询（锁定即停止）；`sync.trigger` 同步执行
//!   一轮并返回变更摘要，`sync.poll` 返回最近一轮摘要与水位；轮询间隔受
//!   冲突风暴退避（指数 ×2 至 24h 上限）；同步状态持久化 `sync-state.json`。
//! - 凭据（WebDAV/S3）存系统钥匙串（service=`lightkey-sync`），不进
//!   vault 密文、不进审计明文、不落日志；`file://` 本地模拟无需凭据。
//! - **并发结构（G1 根治，船长 2026-08-15 定案）**：权限层（`unlock`/会话
//!   令牌）只表达访问资格，不承担互斥；守护进程内部命令与后台同步是自己人，
//!   并发执行；锁只剩数据层内存一致性保护（`SharedDaemon`）：vault 读写锁
//!   （命令读多写少；同步只在应用阶段短时写），同步轮次的网络 I/O 全程
//!   不持锁（`run_sync_round` 两阶段：抓取无锁 → 应用短锁）。

use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
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
    /// M1 同步配置（`lk config sync set` 写入；缺省 = 未配置同步）。
    #[serde(default)]
    pub sync: Option<lk_core::sync::SyncConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            auto_lock_minutes: 5,
            sync: None,
        }
    }
}

/// 同步状态文件名（水位 / 最近摘要 / 风暴等级）。
pub const SYNC_STATE_FILE: &str = "sync-state.json";
/// 钥匙串 service 名（凭据 = `{username, password}` JSON；user = 存储 URL）。
const SYNC_KEYRING_SERVICE: &str = "lightkey-sync";

/// 同步运行状态（持久化到 `sync-state.json`；风暴等级与摘要跨重启保留）。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncRuntime {
    pub state: lk_core::sync::SyncState,
}

impl SyncRuntime {
    fn load(dir: &std::path::Path) -> SyncRuntime {
        match std::fs::read(dir.join(SYNC_STATE_FILE)) {
            Ok(bytes) => serde_json::from_slice::<SyncRuntime>(&bytes).unwrap_or_default(),
            Err(_) => SyncRuntime::default(),
        }
    }

    fn save(&self, dir: &std::path::Path) {
        let path = dir.join(SYNC_STATE_FILE);
        let tmp = path.with_extension("json.tmp");
        if let Ok(bytes) = serde_json::to_vec(&self) {
            if std::fs::write(&tmp, &bytes).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }
}

/// 读配置（守护进程内热更新 / CLI `lk config` 共用）。
pub fn read_config(dir: &std::path::Path) -> Config {
    match std::fs::read(dir.join(CONFIG_FILE)) {
        Ok(bytes) => serde_json::from_slice::<Config>(&bytes).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

/// 写配置（原子：tmp + rename）。
pub fn write_config(dir: &std::path::Path, config: &Config) -> std::io::Result<()> {
    let path = dir.join(CONFIG_FILE);
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(config).unwrap_or_default())?;
    std::fs::rename(&tmp, &path)
}

/// 存同步凭据到系统钥匙串（service=`lightkey-sync`，user=存储 URL）。
pub fn store_sync_credentials(url: &str, username: &str, password: &str) -> Result<(), String> {
    use zeroize::Zeroizing;
    let json = serde_json::json!({ "username": username, "password": password }).to_string();
    let entry = keyring::Entry::new(SYNC_KEYRING_SERVICE, url)
        .map_err(|e| format!("无法访问系统钥匙串：{e}"))?;
    let _ = Zeroizing::new(json.clone());
    entry
        .set_password(&json)
        .map_err(|e| format!("无法写入系统钥匙串：{e}"))
}

/// 读同步凭据（守护进程轮询/触发时用）。`file://` 无需凭据 → `Ok(None)`。
pub fn load_sync_credentials(url: &str) -> Result<Option<lk_core::storage::Credentials>, String> {
    use zeroize::Zeroizing;
    if url.starts_with("file://") {
        return Ok(None);
    }
    let entry = keyring::Entry::new(SYNC_KEYRING_SERVICE, url)
        .map_err(|e| format!("无法访问系统钥匙串：{e}"))?;
    let json = entry
        .get_password()
        .map_err(|e| format!("钥匙串中无 {url} 的凭据（{e}）；请运行 lk config sync set"))?;
    let v: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("钥匙串凭据格式损坏：{e}"))?;
    let username = v
        .get("username")
        .and_then(|u| u.as_str())
        .ok_or_else(|| "钥匙串凭据缺 username".to_string())?
        .to_string();
    let password = v
        .get("password")
        .and_then(|p| p.as_str())
        .ok_or_else(|| "钥匙串凭据缺 password".to_string())?
        .to_string();
    Ok(Some(lk_core::storage::Credentials {
        username,
        password: Zeroizing::new(password),
    }))
}

/// 同步轮次的失败分类（IPC 错误码映射用）。
#[derive(Debug)]
pub enum SyncFail {
    NotConfigured,
    Credentials(String),
    Engine(lk_core::Error),
}

impl SyncFail {
    pub fn message(&self) -> String {
        match self {
            SyncFail::NotConfigured => "未配置同步存储".into(),
            SyncFail::Credentials(m) => m.clone(),
            SyncFail::Engine(e) => e.to_string(),
        }
    }
}

/// `vault.unlock` / `vault.recover` 限流：失败计数 + 指数退避（5 次后 2^(n-5) 秒，封顶 300s）。
#[derive(Debug, Default)]
struct AuthGuard {
    failures: u32,
    blocked_until: Option<Instant>,
}

impl AuthGuard {
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

/// 跨线程共享状态：命令线程（每连接一线程，经命令互斥锁串行）与后台
/// 同步轮询线程并发访问。锁只承担**数据层内存一致性保护**，同步轮次的
/// 网络 I/O 期间不持任何锁（权限语义见模块文档「并发结构」）。
pub struct SharedDaemon {
    /// 数据目录（配置 / 同步状态持久化）。
    pub dir: std::path::PathBuf,
    /// 数据层：解锁态 vault。命令读多写少（读锁）；同步仅在应用阶段短写。
    /// （Arc：同步视图 `LockedVaultView` 与命令侧共用同一把锁。）
    pub vault: Arc<RwLock<Option<UnlockedVault>>>,
    /// 配置（CLI 直接写盘；轮询线程每轮重读热更新）。
    pub config: RwLock<Config>,
    /// 同步运行状态（水位 / 最近摘要 / 风暴等级）。
    pub sync: Mutex<SyncRuntime>,
}

/// 守护进程状态（命令侧；多连接线程经 `Mutex<Daemon>` 串行访问）。
pub struct Daemon {
    sessions: SessionManager,
    audit: AuditLog,
    unlock_guard: AuthGuard,
    recover_guard: AuthGuard,
    last_activity: Instant,
    /// 跨线程共享状态（命令线程与同步轮询线程并发访问）。
    shared: Arc<SharedDaemon>,
}

/// 信号处理标志（unix：SIGINT/SIGTERM 优雅退出）。
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

impl Daemon {
    /// 启动（绑定端点、加载配置、装信号处理）。
    pub fn start(dir: &Path) -> Result<Daemon, String> {
        let dir = dir.to_path_buf();
        let audit = AuditLog::open(&dir).map_err(|e| e.to_string())?;
        let config = load_config(&dir);
        let sync = SyncRuntime::load(&dir);
        install_shutdown_handlers();
        let shared = Arc::new(SharedDaemon {
            dir: dir.clone(),
            vault: Arc::new(RwLock::new(None)),
            config: RwLock::new(config),
            sync: Mutex::new(sync),
        });
        Ok(Daemon {
            sessions: SessionManager::new(),
            audit,
            unlock_guard: AuthGuard::default(),
            recover_guard: AuthGuard::default(),
            last_activity: Instant::now(),
            shared,
        })
    }

    /// 跨线程共享状态引用（命令线程 / 轮询线程共用）。
    pub fn shared(&self) -> Arc<SharedDaemon> {
        Arc::clone(&self.shared)
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
            M_SYNC_TRIGGER => {
                // 生产路径走 main.rs 的 try_sync_trigger（命令锁外执行轮次）；
                // 此处为直接 handle() 调用（测试等）的等价回退
                if self.vault_peek() && self.sessions.validate(token.as_deref().unwrap_or(&[])) {
                    match run_sync_round(&self.shared) {
                        Ok(summary) => RpcResponse::ok(
                            id.clone(),
                            serde_json::to_value(summary).unwrap_or(Value::Null),
                        ),
                        Err(e) => sync_fail_response(id.clone(), &e),
                    }
                } else {
                    session_invalid(id.clone())
                }
            }
            M_SYNC_POLL => self.require_session(id.clone(), token, |me| me.sync_poll(id.clone())),
            // M2 占位
            M_AUTHZ_EVALUATE | M_APPROVAL_REQUEST => {
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
        if self.vault_peek() && self.sessions.validate(token.as_deref().unwrap_or(&[])) {
            f(self)
        } else {
            session_invalid(id)
        }
    }

    /// 解锁态（共享 vault 短读；锁只保护内存一致性）。
    fn vault_peek(&self) -> bool {
        self.shared.vault.read().unwrap().is_some()
    }

    fn vault_status(&self, id: Value) -> RpcResponse {
        let unlocked = self.vault_peek();
        let watermark = self.shared.sync.lock().unwrap().state.watermark.clone();
        let result = StatusResult {
            unlocked,
            version: env!("CARGO_PKG_VERSION").to_string(),
            sync_watermark: watermark,
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    fn vault_init(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: InitParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // 重置会清空当前解锁态 + 重写全部密文：写锁排除同步应用阶段
        // （避免与文件重写竞态；锁只保护数据层内存一致性）
        let result = if p.force {
            let shared = Arc::clone(&self.shared);
            let mut vault_guard = shared.vault.write().unwrap();
            self.lock_internal_locked(&mut vault_guard);
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

    fn vault_lock(&mut self, id: Value) -> RpcResponse {
        self.lock_internal();
        // 空对象而非 null：避免客户端把 result:null 解析为「无 result」
        RpcResponse::ok(id, json!({}))
    }

    /// 锁定：先签名审计事件（用当前 K_audit），再擦除密钥 + 失效令牌 + 删令牌文件。
    fn lock_internal(&mut self) {
        let shared = Arc::clone(&self.shared);
        let mut vault = shared.vault.write().unwrap();
        self.lock_internal_locked(&mut vault);
    }

    /// 锁定（调用方已持 vault 写锁；供锁定/恢复/强制重置共用）。
    fn lock_internal_locked(&mut self, vault: &mut Option<UnlockedVault>) {
        if let Some(v) = vault {
            let _ = self.audit.append(
                v.keys(),
                &EventInput::new("lk", "vault.lock", AuditResult::Allowed),
            );
        }
        *vault = None;
        self.sessions.invalidate();
        self.remove_session_token();
    }

    fn vault_recover(&mut self, id: Value, params: Value) -> RpcResponse {
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
        self.lock_internal_locked(&mut vault_guard);
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
            Err(_) => {
                // 统一：恢复码错误 / 信封损坏 / 未初始化
                self.recover_guard.on_failure();
                RpcResponse::err(id, ERR_VAULT_INVALID, MSG_VAULT_INVALID, None)
            }
        }
    }

    fn auto_lock_if_idle(&mut self) {
        let idle = self.shared.config.read().unwrap().auto_lock_minutes;
        let elapsed = self.last_activity.elapsed();
        let timeout = Duration::from_secs(idle * 60);
        if self.vault_peek() && elapsed >= timeout {
            self.lock_internal();
        }
    }

    fn session_token_path(&self) -> std::path::PathBuf {
        self.shared.dir.join(SESSION_TOKEN_FILE)
    }

    fn write_session_token(&self, token: &[u8; 32]) {
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

    fn remove_session_token(&self) {
        let _ = std::fs::remove_file(self.session_token_path());
    }

    /// 退出清理：删令牌 + 删端点文件（socket 由 OS 回收）。
    pub fn shutdown(&mut self) {
        let saved = { self.shared.sync.lock().unwrap().clone() };
        saved.save(&self.shared.dir);
        self.remove_session_token();
        if let Some(ep) = super::transport::read_endpoint(&self.shared.dir) {
            super::transport::cleanup(&self.shared.dir, &ep);
        }
    }

    // -- 条目 / 审计 -----------------------------------------------------

    fn item_list(&mut self, id: Value) -> RpcResponse {
        // list() 需 &mut（索引自愈）→ 写锁；锁只保护内存一致性，本地操作
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
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
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
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

    // -- 同步（M1）---------------------------------------------------------

    fn sync_poll(&mut self, id: Value) -> RpcResponse {
        let sync = self.shared.sync.lock().unwrap();
        let result = SyncPollResult {
            summary: sync.state.last_summary.clone(),
            watermark: sync.state.watermark.clone(),
        };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    /// `sync.trigger` 无锁路径的会话预检（命令锁内调用）：解锁态 + 令牌有效。
    pub fn trigger_precheck(&self, token: Option<&[u8]>) -> bool {
        self.vault_peek() && self.sessions.validate(token.unwrap_or(&[]))
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

// ---------------------------------------------------------------------------
// 同步轮次（两阶段：抓取无锁 → 应用短锁）与无锁 trigger 路径
// ---------------------------------------------------------------------------

/// [`VaultRead`] 的守护进程侧实现：每次方法调用独立获取**短读锁**（仅本地
/// 内存/磁盘访问），网络 I/O 期间不持任何锁。`keys` 为轮次开始时的快照
/// （应用阶段复核其仍与解锁态一致；锁定/恢复竞态 → 本轮放弃）。
struct LockedVaultView {
    vault: Arc<RwLock<Option<UnlockedVault>>>,
    keys: lk_core::crypto::Keys,
}

impl lk_core::sync::VaultRead for LockedVaultView {
    fn keys(&self) -> lk_core::crypto::Keys {
        self.keys.clone()
    }

    fn index_snapshot(&self) -> lk_core::Result<Vec<lk_core::model::IndexEntry>> {
        let v = self.vault.read().unwrap();
        v.as_ref()
            .map(|v| v.index_snapshot())
            .ok_or(Error::SessionInvalid)
    }

    fn item(&self, id: uuid::Uuid) -> lk_core::Result<lk_core::model::Item> {
        let v = self.vault.read().unwrap();
        v.as_ref().ok_or(Error::SessionInvalid)?.get(id)
    }

    fn item_with_blob(&self, id: uuid::Uuid) -> lk_core::Result<(lk_core::model::Item, Vec<u8>)> {
        let v = self.vault.read().unwrap();
        let v = v.as_ref().ok_or(Error::SessionInvalid)?;
        let item = v.get(id)?;
        let blob = v.item_blob(id)?;
        Ok((item, blob))
    }

    fn tomb_blob(&self, id: uuid::Uuid) -> lk_core::Result<Vec<u8>> {
        let v = self.vault.read().unwrap();
        v.as_ref().ok_or(Error::SessionInvalid)?.tomb_blob(id)
    }

    fn attachment_blobs(
        &self,
        attach_id: uuid::Uuid,
    ) -> lk_core::Result<(lk_core::model::AttachmentMeta, Vec<u8>, Vec<(u32, Vec<u8>)>)> {
        let v = self.vault.read().unwrap();
        let v = v.as_ref().ok_or(Error::SessionInvalid)?;
        let meta = v.attachment_meta(attach_id)?;
        let meta_blob = v.attach_meta_blob(attach_id)?;
        let mut chunks = Vec::with_capacity(meta.chunks as usize);
        for i in 0..meta.chunks {
            chunks.push((i, v.chunk_blob(attach_id, i)?));
        }
        Ok((meta, meta_blob, chunks))
    }

    fn attachment_keys(&self, attach_id: uuid::Uuid) -> Vec<String> {
        self.vault
            .read()
            .unwrap()
            .as_ref()
            .map(|v| v.attachment_keys(attach_id))
            .unwrap_or_default()
    }

    fn tombstones(&self) -> lk_core::Result<Vec<(uuid::Uuid, lk_core::model::Tombstone)>> {
        let v = self.vault.read().unwrap();
        v.as_ref()
            .map(|v| v.tombstones())
            .ok_or(Error::SessionInvalid)
    }
}

/// 执行一轮同步（守护进程侧；轮询线程与 `sync.trigger` 共用）。
///
/// 两阶段（网络 I/O 全程不持任何守护进程锁）：
///
/// 1. 抓取：密钥/索引等经 [`LockedVaultView`] 短读锁读取 + 全部网络 I/O；
/// 2. 应用：vault 短写锁内按当前状态复核后落盘（CAS 兜底，见引擎文档）。
///
/// 锁/恢复竞态（密钥已变）→ 本轮放弃（Err），下一轮重试。
/// 水位/摘要/风暴等级在锁外持久化。
pub fn run_sync_round(
    shared: &SharedDaemon,
) -> std::result::Result<lk_core::sync::SyncSummary, SyncFail> {
    use lk_core::storage::{backend_from_url, StorageBackend};
    // 配置热更新（CLI 直接写盘；每轮重读）
    let fresh = read_config(&shared.dir);
    *shared.config.write().unwrap() = fresh.clone();
    let cfg = fresh.sync.clone().ok_or(SyncFail::NotConfigured)?;
    if cfg.validate().is_err() {
        return Err(SyncFail::NotConfigured);
    }
    let creds = load_sync_credentials(&cfg.url).map_err(SyncFail::Credentials)?;
    let backend: Box<dyn StorageBackend> =
        backend_from_url(&cfg.url, creds).map_err(SyncFail::Engine)?;
    run_sync_round_with(shared, backend)
}

/// 执行一轮同步（后端注入；并发回归测试用）。
pub fn run_sync_round_with(
    shared: &SharedDaemon,
    backend: Box<dyn lk_core::storage::StorageBackend>,
) -> std::result::Result<lk_core::sync::SyncSummary, SyncFail> {
    use lk_core::sync::{storm_level_after, SyncEngine};
    // 密钥快照（短读锁；视图其余读取按需短锁）
    let keys = {
        let vault = shared.vault.read().unwrap();
        let v = vault
            .as_ref()
            .ok_or(SyncFail::Engine(Error::SessionInvalid))?;
        v.keys().clone()
    };
    let view = LockedVaultView {
        vault: Arc::clone(&shared.vault),
        keys: keys.clone(),
    };
    // 阶段 1：抓取（只读本地 + 全部网络 I/O；不持锁）
    let engine = SyncEngine::new(backend.as_ref());
    let mut plan = engine
        .fetch_round(&view, &lk_core::crypto::now_iso())
        .map_err(SyncFail::Engine)?;
    // 阶段 2：应用（短写锁；网络已完成）
    {
        let mut guard = shared.vault.write().unwrap();
        let vault = guard
            .as_mut()
            .ok_or(SyncFail::Engine(Error::SessionInvalid))?;
        // 锁/恢复竞态：密钥已变 → 本轮放弃（下轮以新钥重试）
        if vault.keys().k_data.as_ref() != keys.k_data.as_ref() {
            return Err(SyncFail::Engine(Error::SessionInvalid));
        }
        engine
            .apply_round(vault, &mut plan)
            .map_err(SyncFail::Engine)?;
    }
    // 水位 / 摘要 / 风暴等级（小锁；锁外持久化）
    let saved = {
        let mut sync = shared.sync.lock().unwrap();
        sync.state.watermark = Some(lk_core::crypto::now_iso());
        sync.state.last_summary = Some(plan.summary.clone());
        sync.state.storm_level = storm_level_after(
            plan.summary.pulled + plan.summary.pushed,
            sync.state.storm_level,
        );
        sync.clone()
    };
    saved.save(&shared.dir);
    Ok(plan.summary)
}

/// `sync.trigger` 的无锁路径：会话预检（短暂持命令锁）→ 轮次主体在命令锁
/// 外执行（网络 I/O 不阻塞其他命令；与后台轮询并发安全——数据层 CAS +
/// vault 短写锁兜底）。非 trigger 请求 → `None`（走常规命令路径）。
pub fn try_sync_trigger(
    state: &Mutex<Daemon>,
    shared: &SharedDaemon,
    line: &str,
) -> Option<String> {
    let req: RpcRequest = serde_json::from_str(line).ok()?;
    if req.method != M_SYNC_TRIGGER {
        return None;
    }
    let id = req.id;
    let token = extract_token(&req.params);
    // 会话预检（短暂持命令锁；含空闲超时检查）
    let session_ok = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        guard.trigger_precheck(token.as_deref())
    };
    if !session_ok {
        return Some(serde_json::to_string(&session_invalid(id)).unwrap_or_else(|_| "{}".into()));
    }
    // 轮次：命令锁外执行（网络 I/O 期间其他命令照常服务）
    let resp = match run_sync_round(shared) {
        Ok(summary) => RpcResponse::ok(id, serde_json::to_value(summary).unwrap_or(Value::Null)),
        Err(e) => sync_fail_response(id, &e),
    };
    // 活动时间戳（命令锁内；与常规路径的 last_activity 语义一致）
    if let Ok(mut guard) = state.lock() {
        guard.last_activity = Instant::now();
    }
    Some(serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into()))
}

/// 同步失败分类 → IPC 错误响应（与 M1 原有映射一致）。
fn sync_fail_response(id: Value, e: &SyncFail) -> RpcResponse {
    match e {
        SyncFail::NotConfigured => {
            RpcResponse::err(id, ERR_SYNC_NOT_CONFIGURED, MSG_SYNC_NOT_CONFIGURED, None)
        }
        SyncFail::Credentials(msg) => RpcResponse::err(
            id,
            ERR_SYNC_CREDENTIALS,
            MSG_SYNC_CREDENTIALS,
            Some(json!({ "detail": msg })),
        ),
        SyncFail::Engine(e) => {
            let (code, msg) = match e {
                Error::SyncStorage(_) => (ERR_SYNC_STORAGE, MSG_SYNC_STORAGE),
                Error::SyncAnomaly(_) => (ERR_SYNC_ANOMALY, MSG_SYNC_ANOMALY),
                Error::SyncConfig(_) => (ERR_SYNC_NOT_CONFIGURED, MSG_SYNC_NOT_CONFIGURED),
                _ => (ERR_SYNC_STORAGE, MSG_SYNC_STORAGE),
            };
            RpcResponse::err(id, code, msg, Some(json!({ "detail": e.to_string() })))
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

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::audit::AuditLog;
    use lk_core::crypto::test_kdf_params;
    use lk_core::storage::{GetResult, LocalStorage, PutOutcome, RemoteObject};
    use lk_core::sync::SyncConfig;
    use lk_core::vault::init_vault_with_params;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    /// 慢网络后端：get/put 注入固定延迟，并在每次慢调用开始时发信号
    /// （测试借此确定同步线程正处在网络 I/O 中——即「持锁窗口」）。
    struct SlowBackend {
        inner: LocalStorage,
        delay: Duration,
        signals: mpsc::Sender<()>,
    }

    impl lk_core::storage::StorageBackend for SlowBackend {
        fn name(&self) -> &'static str {
            "slow"
        }
        fn get(&self, key: &str) -> lk_core::Result<Option<GetResult>> {
            let _ = self.signals.send(());
            std::thread::sleep(self.delay);
            self.inner.get(key)
        }
        fn put(
            &self,
            key: &str,
            data: &[u8],
            expected: Option<&str>,
        ) -> lk_core::Result<PutOutcome> {
            let _ = self.signals.send(());
            std::thread::sleep(self.delay);
            self.inner.put(key, data, expected)
        }
        fn delete(&self, key: &str) -> lk_core::Result<()> {
            let _ = self.signals.send(());
            std::thread::sleep(self.delay);
            self.inner.delete(key)
        }
        fn list(&self) -> lk_core::Result<Vec<RemoteObject>> {
            let _ = self.signals.send(());
            std::thread::sleep(self.delay);
            self.inner.list()
        }
        fn etag(&self, key: &str) -> lk_core::Result<Option<String>> {
            let _ = self.signals.send(());
            std::thread::sleep(self.delay);
            self.inner.etag(key)
        }
    }

    /// 构造 JSON-RPC 请求行。
    fn rpc_line(method: &str, token: Option<&str>, params: Value) -> String {
        let mut p = params;
        if let Some(t) = token {
            p["token"] = json!(t);
        }
        serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": p
        }))
        .unwrap()
    }

    fn rpc_result(resp: &str) -> Value {
        serde_json::from_str::<Value>(resp).unwrap()["result"].clone()
    }

    /// G1 根治回归：同步轮次进行中（慢网络后端持网络 I/O 窗口），
    /// 前台命令不被阻塞；且轮次应用阶段不覆盖同步期间命令的更新。
    ///
    /// 场景：远端有较新 X（拉取）+ 本地新增 Y（推送）→ 轮次含 3 个慢
    /// 网络窗口（拉 X / 推 Y / 写索引）。在每个窗口内发命令：
    /// 1. 拉 X 窗口 → `item.list` 必须及时返回（不等待网络）；
    /// 2. 推 Y 窗口 → `item.put` 更新 X（本地 rev 前进，CAS 通过）
    ///    ——轮次应用阶段 LWW 复核后跳过旧快照导入，X 不被覆盖；
    /// 3. 写索引窗口 → 轮次完成，摘要 pulled=0（复核跳过）、pushed=1。
    #[test]
    fn sync_round_does_not_block_commands_and_apply_respects_races() {
        // 夹具：真实守护进程（快速 KDF）+ 双端远端布局
        let dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        {
            let mut audit = AuditLog::open(dir.path()).unwrap();
            init_vault_with_params(dir.path(), "pw", false, &mut audit, &test_kdf_params())
                .unwrap();
        }
        let mut daemon = Daemon::start(dir.path()).unwrap();
        // 解锁
        let unlock = rpc_result(&daemon.handle(&rpc_line(
            M_VAULT_UNLOCK,
            None,
            json!({ "masterPassword": "pw" }),
        )));
        let token = unlock["token"].as_str().unwrap().to_string();
        // 配置同步（file://；后端注入，URL 仅用于校验）
        {
            let cfg = Config {
                auto_lock_minutes: 60,
                sync: Some(SyncConfig {
                    url: "file:///unused".into(),
                    interval_secs: 60,
                }),
            };
            *daemon.shared().config.write().unwrap() = cfg;
        }
        // 建条目 X
        let put_x = rpc_result(&daemon.handle(&rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                "type": "login", "name": "X", "username": "u1",
                "password": "p1", "uris": [], "custom": []
            } }),
        )));
        let x_id = put_x["item"]["id"].as_str().unwrap().to_string();
        let x_rev1 = put_x["item"]["revision"].as_str().unwrap().to_string();
        // 基线轮（正常速度）：远端建立 index + X rev1
        let shared = daemon.shared();
        run_sync_round_with(
            &shared,
            Box::new(LocalStorage::new(remote_dir.path().to_path_buf())),
        )
        .unwrap();
        // 远端较新 X（rev2）：用第二个客户端（同钥拷贝）编辑并同步
        {
            let b_dir = tempfile::tempdir().unwrap();
            for name in ["vault.json", "index.lk", "audit.log", "recovery.envelope"] {
                std::fs::copy(dir.path().join(name), b_dir.path().join(name)).unwrap();
            }
            for entry in std::fs::read_dir(dir.path()).unwrap() {
                let name = entry.unwrap().file_name().to_string_lossy().to_string();
                if name.ends_with(".item.lk") {
                    std::fs::copy(dir.path().join(&name), b_dir.path().join(&name)).unwrap();
                }
            }
            let mut b = UnlockedVault::unlock(b_dir.path(), "pw").unwrap();
            b.put(
                Some(uuid::Uuid::parse_str(&x_id).unwrap()),
                lk_core::model::ItemDraft::Login {
                    name: "X".into(),
                    username: "remote-new".into(),
                    password: "p1".into(),
                    uris: vec![],
                    custom: vec![],
                },
                Some(x_rev1.clone()),
            )
            .unwrap();
            use lk_core::sync::SyncEngine;
            SyncEngine::new(&LocalStorage::new(remote_dir.path().to_path_buf()))
                .run_round(&mut b, &lk_core::crypto::now_iso())
                .unwrap();
        }
        // 本地新增 Y（推送候选）；慢后端注入
        daemon.handle(&rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({ "item": {
                    "type": "login", "name": "Y", "username": "u2",
                    "password": "p2", "uris": [], "custom": []
                } }),
        ));
        let (tx, rx) = mpsc::channel();
        let slow = Box::new(SlowBackend {
            inner: LocalStorage::new(remote_dir.path().to_path_buf()),
            delay: Duration::from_millis(400),
            signals: tx,
        });
        // 同步线程：轮次（抓取无锁 → 应用短锁）
        let round_shared = Arc::clone(&shared);
        let round = std::thread::spawn(move || run_sync_round_with(&round_shared, slow));

        // 窗口 1：拉 X 的网络 I/O 中 → 前台命令及时返回（不等待网络）
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let t0 = Instant::now();
        let list = daemon.handle(&rpc_line(M_ITEM_LIST, Some(&token), json!({})));
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(300),
            "item.list 在同步网络 I/O 中被阻塞 {elapsed:?}"
        );
        assert_eq!(rpc_result(&list)["items"].as_array().unwrap().len(), 2);

        // 窗口 2：推 Y 的网络 I/O 中 → 命令更新 X（CAS rev1 → rev2'）
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let put = daemon.handle(&rpc_line(
            M_ITEM_PUT,
            Some(&token),
            json!({
                "id": x_id,
                "expectedRevision": x_rev1,
                "item": {
                    "type": "login", "name": "X", "username": "local-race",
                    "password": "p1", "uris": [], "custom": []
                }
            }),
        ));
        let put_result = rpc_result(&put);
        assert!(
            put_result["item"]["id"].as_str().is_some(),
            "命令更新在同步网络 I/O 中被阻塞或被拒绝：{put}"
        );

        // 窗口 3：写索引的网络 I/O 中（轮次将完成）
        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        // 轮次完成：应用阶段 LWW 复核 → 跳过旧快照导入（X 不被覆盖）
        let summary = round.join().unwrap().unwrap();
        assert_eq!(summary.pulled, 0, "应用复核跳过旧快照导入");
        assert_eq!(summary.pushed, 1, "Y 已推送");
        let x =
            rpc_result(&daemon.handle(&rpc_line(M_ITEM_GET, Some(&token), json!({ "id": x_id }))));
        assert_eq!(
            x["username"].as_str().unwrap(),
            "local-race",
            "同步期间命令的更新不被轮次覆盖"
        );
        // 水位已推进（轮次成功）
        let status = rpc_result(&daemon.handle(&rpc_line(M_VAULT_STATUS, None, json!({}))));
        assert!(status["syncWatermark"].as_str().is_some());
    }
}
