//! C 层 daemon 宿主（`docs/plugin-architecture.md` §3.3；决策 #2 A：**下沉为
//! 共享 crate**，供 `lk-cli`（`lk daemon`）与桌面应用内置实例（M2 desktop
//! 任务）复用，行为不回归）。
//!
//! 边界（与 M1.5 一致，仅搬移 + M2 增量）：
//!
//! - [`lib`]（本模块）：状态机 + JSON-RPC 分发 + 装配点（[`CoreServices`]：
//!   事件总线 + 服务）+ 授权门三阶段编排（G1）；
//! - [`config`]：`config.json` / `sync-state.json` 读写 + 同步凭据钥匙串；
//! - [`sync`]：同步轮次执行（抓取无锁 → 应用短锁）；
//! - [`transport`]：本地 IPC 传输（UDS / named pipe）+ 对端身份（PID/cwd）
//!   + **通知订阅连接**（决策 #3 A：JSON-RPC notification 推送）；
//! - [`notifier`]：事件总线 → 通知帧的 EventSink（非阻塞广播）。
//!
//! M2 增量（详见各模块文档）：
//!
//! - `authz.evaluate` 三阶段（命令锁内第 1/2 层 + 登记审批 → 锁外 30s 等待 →
//!   重取锁收尾）：第 3 层等待**不持有命令锁**（G1 回归）；
//! - `rule.add|list|remove`（决策 #6）；`approval.result` 回传；`subscribe`
//!   推送订阅；
//! - 启动者判定在守护进程侧从 IPC 对端 PID 回溯（[`lk_core::starter`]），
//!   客户端自报字段一律不信任。

pub mod config;
pub mod dirs;
pub mod notifier;
pub mod sync;
pub mod transport;

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use lk_core::audit::{AuditChannel, AuditLog, AuditResult, EventInput};
use lk_core::authz::{
    ApprovalChannel, ApprovalDecision, ApprovalRequest, AuthzGate, AuthzRequest, DenyReason,
    LayerResult, LocalApprovalChannel, PendingApprovals,
};
use lk_core::bus::LockReason;
use lk_core::ipc::*;
use lk_core::model::{Rule, RuleDraft};
use lk_core::recovery::RecoveryCode;
use lk_core::service::CoreServices;
use lk_core::session::SessionManager;
use lk_core::starter::{self, UNKNOWN_STARTER};
use lk_core::vault::{self, UnlockedVault};
use lk_core::{Error, Result};
use serde_json::{json, Value};
use sha2::Digest;

pub use config::*;
pub use notifier::{frame_for_event, Notifier};
pub use sync::sync_fail_response;
pub use sync::{run_sync_round, run_sync_round_with, try_sync_trigger};
pub use transport::{PeerInfo, PushHub};

/// 会话令牌文件名（0600；CLI 进程间传递，锁定即删除）。
pub const SESSION_TOKEN_FILE: &str = "session.token";

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
    /// 待审批注册表（跨线程：命令线程登记/等待，`approval.result` 回传线程写入）。
    pub approvals: Arc<PendingApprovals>,
    /// 推送通道（通知订阅连接集合；`subscriber_count>0` = 桌面壳已订阅 =
    /// 有审批界面）。
    pub push: Arc<PushHub>,
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
    /// C 层装配（事件总线 + 无状态地基服务；session/vault 经其挂总线）。
    core: CoreServices,
    /// 授权门（第 1/2 层短路 + 第 3 层审批编排）。
    gate: AuthzGate,
    /// 进行中的授权判定（第 3 层等待期间持有；request_id → 请求原文）。
    pending_authz: Mutex<HashMap<uuid::Uuid, PendingAuthz>>,
}

/// 授权判定第 3 层的待办（等待期间由发起连接线程持有，锁外等待）。
struct PendingAuthz {
    request: AuthzRequest,
}

/// 信号处理标志（unix：SIGINT/SIGTERM 优雅退出）。
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

impl Daemon {
    /// 启动（加载配置、装配总线/授权门/通知桥）。
    pub fn start(dir: &Path) -> std::result::Result<Daemon, String> {
        let dir = dir.to_path_buf();
        let audit = AuditLog::open(&dir).map_err(|e| e.to_string())?;
        let config = load_config(&dir);
        let sync = SyncRuntime::load(&dir);
        install_shutdown_handlers();
        let core = CoreServices::new();
        let sessions = core.new_session();
        // M2 装配：待审批注册表 + 推送通道 + 本地审批通道 + 通知桥
        // （通知桥订阅总线：Rust 事件 → notification 帧 → 订阅连接，非阻塞）
        let approvals = Arc::new(PendingApprovals::new());
        let push = PushHub::new();
        let approval: Arc<dyn ApprovalChannel> = Arc::new(LocalApprovalChannel::new(
            Arc::clone(&approvals),
            Arc::clone(core.bus()),
            Box::new({
                let push = Arc::clone(&push);
                move || push.subscriber_count() > 0
            }),
        ));
        core.subscribe(Arc::new(Notifier::new(Arc::clone(&push))));
        let gate = AuthzGate::new(approval);
        let shared = Arc::new(SharedDaemon {
            dir: dir.clone(),
            vault: Arc::new(RwLock::new(None)),
            config: RwLock::new(config),
            sync: Mutex::new(sync),
            approvals,
            push,
        });
        Ok(Daemon {
            sessions,
            audit,
            unlock_guard: AuthGuard::default(),
            recover_guard: AuthGuard::default(),
            last_activity: Instant::now(),
            shared,
            core,
            gate,
            pending_authz: Mutex::new(HashMap::new()),
        })
    }

    /// 跨线程共享状态引用（命令线程 / 轮询线程共用）。
    pub fn shared(&self) -> Arc<SharedDaemon> {
        Arc::clone(&self.shared)
    }

    /// 事件总线引用（测试装配用）。
    pub fn bus(&self) -> &Arc<lk_core::bus::EventBus> {
        self.core.bus()
    }

    /// 处理一行 JSON-RPC 请求，返回一行响应（永不 panic）。
    /// `peer` 为 IPC 对端身份（PID/cwd，由传输层派生——授权路径不信任客户端）。
    pub fn handle(&mut self, line: &str, peer: &PeerInfo) -> String {
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
        self.dispatch(req, peer)
    }

    fn dispatch(&mut self, req: RpcRequest, _peer: &PeerInfo) -> String {
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
                // 生产路径走 make_handler 的 try_sync_trigger（命令锁外执行轮次）；
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
            // M2：通知订阅（连接转入流模式由传输层处理；此处只做会话校验）
            M_SUBSCRIBE => self.require_session(id.clone(), token, |me| me.subscribe(id.clone())),
            M_APPROVAL_RESULT => self.require_session(id.clone(), token, |me| {
                me.approval_result(id.clone(), params)
            }),
            M_RULE_ADD => {
                self.require_session(id.clone(), token, |me| me.rule_add(id.clone(), params))
            }
            M_RULE_LIST => {
                self.require_session(id.clone(), token, |me| me.rule_list(id.clone(), params))
            }
            M_RULE_REMOVE => {
                self.require_session(id.clone(), token, |me| me.rule_remove(id.clone(), params))
            }
            // authz.evaluate 走 make_handler 的三阶段特殊路径（G1：等待不持
            // 命令锁）；直接 handle() 调用不提供（返回 method-not-found）
            M_AUTHZ_EVALUATE => {
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

    fn vault_lock(&mut self, id: Value) -> RpcResponse {
        self.lock_internal();
        // 空对象而非 null：避免客户端把 result:null 解析为「无 result」
        RpcResponse::ok(id, json!({}))
    }

    /// 锁定：先签名审计事件（用当前 K_audit），再擦除密钥 + 失效令牌 + 删令牌文件。
    /// 默认 reason = manual（`lock_internal_with` 可指定）。
    fn lock_internal(&mut self) {
        self.lock_internal_with(LockReason::Manual);
    }

    /// 锁定（`reason` 进 `session.locked` 事件负载）。
    fn lock_internal_with(&mut self, reason: LockReason) {
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
    fn lock_internal_locked(&mut self, vault: &mut Option<UnlockedVault>, reason: LockReason) {
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

    fn auto_lock_if_idle(&mut self) {
        let idle = self.shared.config.read().unwrap().auto_lock_minutes;
        let elapsed = self.last_activity.elapsed();
        let timeout = Duration::from_secs(idle * 60);
        if self.vault_peek() && elapsed >= timeout {
            self.lock_internal_with(LockReason::Timeout);
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
        // 广播 `session.locked(daemon-exit)`（进程退出前的最后事件）
        self.sessions.invalidate_with(LockReason::DaemonExit);
        self.remove_session_token();
        if let Some(ep) = transport::read_endpoint(&self.shared.dir) {
            transport::cleanup(&self.shared.dir, &ep);
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

    // -- M2：规则 / 审批回传 / 订阅 ---------------------------------------

    /// `subscribe`：会话校验已由 require_session 完成；响应 ok 后传输层把
    /// 连接转入流模式（通知订阅）。
    fn subscribe(&mut self, id: Value) -> RpcResponse {
        RpcResponse::ok(id, json!({}))
    }

    /// `approval.result`：审批回传（决策权始终在 Rust 侧）。伪造/已超时的
    /// requestId → 忽略（`accepted=false`，testing.md 第三层 #17）。
    fn approval_result(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: ApprovalResultParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let decision = match p.decision.as_str() {
            "allowed" => ApprovalDecision::Allowed,
            "denied" => ApprovalDecision::Denied,
            _ => {
                return RpcResponse::err(
                    id,
                    ERR_INVALID_PARAMS,
                    "invalid params",
                    Some(json!({ "detail": "decision 须为 allowed | denied" })),
                )
            }
        };
        let accepted = self.shared.approvals.resolve(p.request_id, decision);
        let result = ApprovalResultOutcome { accepted };
        RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
    }

    /// `rule.add`：跨命名空间归一化 → 校验 → canonicalize → 入库（vault
    /// 写锁）+ 审计（channel 区分 cli/desktop/wsl-bridge；testing.md 第三层
    /// #19 超长/非法拒绝）。
    fn rule_add(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: RuleAddParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        // projectDir 入库基准（cross-subsystem.md §7.4，两侧同函数）：先过
        // 跨命名空间归一化——UNC / verbatim 包裹的 WSL 路径折算为
        // `wsl://<distro>/<rest>` 规范形；常规路径维持原语义。
        let project_dir_input = lk_core::path_ns::canonical_project_dir(&p.project_dir);
        if let Err(e) = validate_rule_fields(&project_dir_input, &p.name, &p.command, &p.keys) {
            return RpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "invalid params",
                Some(json!({ "detail": e })),
            );
        }
        let channel = audit_channel(p.channel.as_deref());
        // wsl:// 规范形直接入库（非本机 fs 路径）；常规路径仍以 canonical
        // 形态入库（解析符号链接），并经与运行时 cwd 判定同一个归一化函数
        // 剥离 Windows verbatim 前缀（§7.4 两侧同函数，存储形态 == 判定形态）
        let project_dir = if lk_core::path_ns::is_wsl_canonical(&project_dir_input) {
            project_dir_input.clone()
        } else {
            match std::fs::canonicalize(&project_dir_input) {
                Ok(c) => lk_core::path_ns::canonical_project_dir(&c.to_string_lossy()),
                Err(_) => {
                    return RpcResponse::err(
                        id,
                        ERR_INVALID_PARAMS,
                        "invalid params",
                        Some(
                            json!({ "detail": format!("projectDir 无法解析：{}", p.project_dir) }),
                        ),
                    )
                }
            }
        };
        let draft = RuleDraft {
            project_dir,
            name: p.name.clone(),
            command: p.command.clone(),
            keys: p.keys.clone(),
        };
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.put_rule(draft, None) {
            Ok(rule) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: "lk".into(),
                        target: "daemon".into(),
                        command: format!("rule.add {}", p.name),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                let result = RuleAddResult { rule };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    /// `rule.list`：解密态规则（规则库损坏 → fail-closed 报错）。
    fn rule_list(&mut self, id: Value, params: Value) -> RpcResponse {
        let channel = match serde_json::from_value::<RuleListParams>(params) {
            Ok(p) => audit_channel(p.channel.as_deref()),
            Err(_) => AuditChannel::Cli,
        };
        let shared = Arc::clone(&self.shared);
        let guard = shared.vault.read().unwrap();
        let me = guard.as_ref().unwrap();
        match me.list_rules() {
            Ok(rules) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: "lk".into(),
                        target: "daemon".into(),
                        command: "rule.list".into(),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                let result = RuleListResult { rules };
                RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    /// `rule.remove`：软删除（墓碑；删除随同步传播）+ 审计。
    fn rule_remove(&mut self, id: Value, params: Value) -> RpcResponse {
        let p: RuleRemoveParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => return RpcResponse::err(id, ERR_INVALID_PARAMS, "invalid params", None),
        };
        let channel = audit_channel(p.channel.as_deref());
        let shared = Arc::clone(&self.shared);
        let mut guard = shared.vault.write().unwrap();
        let me = guard.as_mut().unwrap();
        match me.delete_rule(p.id) {
            Ok(_tomb) => {
                let _ = self.audit.append(
                    me.keys(),
                    &EventInput {
                        starter: "lk".into(),
                        target: "daemon".into(),
                        command: format!("rule.remove {}", p.id),
                        result: AuditResult::Allowed,
                        channel,
                        old_key_id: None,
                        new_key_id: None,
                    },
                );
                RpcResponse::ok(id, json!({}))
            }
            Err(e) => self.err_response(id, &e),
        }
    }

    // -- M2：授权门三阶段编排 ---------------------------------------------

    /// 审批超时（config 可配；默认 30s，第 3 层超时默认拒绝）。
    fn approval_timeout(&self) -> u64 {
        self.shared
            .config
            .read()
            .unwrap()
            .approval_timeout_secs
            .max(1)
    }

    /// 阶段①（命令锁内）：会话预检 + 启动者判定 + 第 1/2 层短路；需要审批
    /// 时登记待审批 + 广播 `authz.request`，返回 Pending（等待移出命令锁）。
    fn authz_begin(&mut self, id: Value, params: Value, peer: &PeerInfo) -> AuthzBegin {
        let p: AuthzEvaluateParams = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(_) => {
                return AuthzBegin::Final(rpc_string(RpcResponse::err(
                    id,
                    ERR_INVALID_PARAMS,
                    "invalid params",
                    None,
                )))
            }
        };
        if let Err(e) = validate_evaluate_fields(&p.command, &p.keys) {
            return AuthzBegin::Final(rpc_string(RpcResponse::err(
                id,
                ERR_INVALID_PARAMS,
                "invalid params",
                Some(json!({ "detail": e })),
            )));
        }
        let channel = audit_channel(p.channel.as_deref());
        // 启动者判定：守护进程侧从 IPC 对端 PID 回溯（客户端自报字段不信任）
        let starter = derive_starter(peer);
        // cwd 以对端真实 cwd（canonical）为准；客户端自报 cwd 仅作提示（忽略）。
        // 跨命名空间归一化（cross-subsystem.md §7.4，两侧同函数）：WSL UNC /
        // verbatim 形态折算为 `wsl://<distro>/<rest>` 规范形后再做祖先匹配，
        // 与 rule.add 入库基准一致——伪造 cwd 写法变体不得绕过或漏配。
        let cwd = lk_core::path_ns::canonical_project_dir(&peer.cwd.clone().unwrap_or_default());
        let req = AuthzRequest {
            starter,
            cwd,
            command: p.command,
            keys: p.keys,
        };
        let shared = Arc::clone(&self.shared);
        let vault = shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return AuthzBegin::Final(
                serde_json::to_string(&session_invalid(id)).unwrap_or_else(|_| "{}".into()),
            );
        };
        // 单次扫描 secret 索引（批量解析请求 key；避免逐 key 全表扫描）
        let secrets = v.secret_values().unwrap_or_default();
        let result = self
            .gate
            .evaluate_layers(&req, &VaultRuleView { vault: v, secrets });
        drop(vault);
        match result {
            LayerResult::Allowed { keys } => {
                // 第 2 层命中：解密注入值 + 审计 allowed（caller channel）
                match self.resolve_env(&keys) {
                    Ok(env) => {
                        self.audit_authz(&req, channel, AuditResult::Allowed);
                        AuthzBegin::Final(rpc_string(RpcResponse::ok(
                            id,
                            serde_json::to_value(AuthzEvaluateResult {
                                allowed: true,
                                reason: None,
                                env: Some(env),
                            })
                            .unwrap_or(Value::Null),
                        )))
                    }
                    Err(e) => AuthzBegin::Final(rpc_string(self.err_response(id, &e))),
                }
            }
            LayerResult::Denied { reason } => {
                // 第 1 层：拒绝（不弹窗、不留内容，仅审计拒绝事件）
                self.audit_authz(&req, channel, AuditResult::Denied);
                AuthzBegin::Final(rpc_string(RpcResponse::ok(
                    id,
                    serde_json::to_value(AuthzEvaluateResult {
                        allowed: false,
                        reason: Some(reason.as_str().to_string()),
                        env: None,
                    })
                    .unwrap_or(Value::Null),
                )))
            }
            LayerResult::NeedsApproval => {
                // 第 3 层：无审批界面 → fail-closed 立即拒绝（不阻塞）
                if !self.gate.approval().available() {
                    self.audit_authz(&req, channel, AuditResult::Denied);
                    return AuthzBegin::Final(rpc_string(RpcResponse::ok(
                        id,
                        serde_json::to_value(AuthzEvaluateResult {
                            allowed: false,
                            reason: Some(DenyReason::NoUi.as_str().to_string()),
                            env: None,
                        })
                        .unwrap_or(Value::Null),
                    )));
                }
                // 登记待审批 + 广播 `authz.request`（命令锁内、非阻塞）
                let request_id = lk_core::crypto::random_uuid();
                let expires_at = Instant::now() + Duration::from_secs(self.approval_timeout());
                let areq = ApprovalRequest {
                    request_id,
                    starter: req.starter.clone(),
                    project_dir: req.cwd.clone(),
                    command: req.command.clone(),
                    keys: req.keys.clone(),
                };
                self.gate.approval().open(&areq, expires_at);
                self.pending_authz
                    .lock()
                    .unwrap()
                    .insert(request_id, PendingAuthz { request: req });
                AuthzBegin::Pending {
                    request_id,
                    expires_at,
                }
            }
        }
    }

    /// 阶段③（重取命令锁）：收决策 → 解密 key 值 → 审计（channel=Approval）
    /// → 返回。等待期间锁定 → `session.invalid`（无法解密/审计）。
    fn authz_finalize(
        &mut self,
        id: Value,
        request_id: uuid::Uuid,
        decision: ApprovalDecision,
    ) -> String {
        let pending = self.pending_authz.lock().unwrap().remove(&request_id);
        let Some(pending) = pending else {
            // 条目已被消费（极端竞态）→ 保守拒绝
            return rpc_string(RpcResponse::ok(
                id,
                serde_json::to_value(AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Rejected.as_str().to_string()),
                    env: None,
                })
                .unwrap_or(Value::Null),
            ));
        };
        let result = match decision {
            ApprovalDecision::Allowed => {
                match self.resolve_env(&pending.request.keys) {
                    Ok(env) => {
                        self.audit_authz(
                            &pending.request,
                            AuditChannel::Approval,
                            AuditResult::Allowed,
                        );
                        AuthzEvaluateResult {
                            allowed: true,
                            reason: None,
                            env: Some(env),
                        }
                    }
                    Err(_) => {
                        // 等待期间锁定/密钥不可用 → 无法满足
                        return serde_json::to_string(&session_invalid(id))
                            .unwrap_or_else(|_| "{}".into());
                    }
                }
            }
            ApprovalDecision::Denied => {
                self.audit_authz(
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Denied,
                );
                AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Rejected.as_str().to_string()),
                    env: None,
                }
            }
            ApprovalDecision::Timeout => {
                self.audit_authz(
                    &pending.request,
                    AuditChannel::Approval,
                    AuditResult::Timeout,
                );
                AuthzEvaluateResult {
                    allowed: false,
                    reason: Some(DenyReason::Timeout.as_str().to_string()),
                    env: None,
                }
            }
        };
        rpc_string(RpcResponse::ok(
            id,
            serde_json::to_value(result).unwrap_or(Value::Null),
        ))
    }

    /// 解析注入 env（vault 读锁内；key 名 → 值；仅被授权 key；单次扫描）。
    fn resolve_env(&self, keys: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
        let vault = self.shared.vault.read().unwrap();
        let v = vault.as_ref().ok_or(Error::SessionInvalid)?;
        let all = v.secret_values()?;
        let mut env = std::collections::BTreeMap::new();
        for k in keys {
            if let Some(value) = all.get(k) {
                env.insert(k.clone(), value.clone());
            }
        }
        Ok(env)
    }

    /// 授权路径审计（starter 为进程链回溯结果；command 为命令摘要，脱敏：
    /// `lk inject <sha256:8>`，audit.md §2）。
    fn audit_authz(&self, req: &AuthzRequest, channel: AuditChannel, result: AuditResult) {
        let digest = sha2::Sha256::digest(req.command.as_bytes());
        let short: String = hex::encode(&digest[..4]);
        let target = req
            .command
            .split_whitespace()
            .next()
            .unwrap_or("lk")
            .to_string();
        let vault = self.shared.vault.read().unwrap();
        let Some(v) = vault.as_ref() else {
            return; // 已锁定 → 无法签名（K_audit 已擦除）
        };
        let keys = v.keys().clone();
        drop(vault);
        let _ = self.audit.append(
            &keys,
            &EventInput {
                starter: req.starter.clone(),
                target,
                command: format!("lk inject <{short}>"),
                result,
                channel,
                old_key_id: None,
                new_key_id: None,
            },
        );
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
// 授权门装配辅助
// ---------------------------------------------------------------------------

/// 授权门第 1/2 层需要的 vault 视图（守护进程 vault 读锁内实现）。
/// secrets 为**单次扫描**产物（一次 evaluate 只扫一遍 vault，避免逐 key 扫描）。
struct VaultRuleView<'a> {
    vault: &'a UnlockedVault,
    secrets: std::collections::HashMap<String, String>,
}

impl lk_core::authz::RuleVault for VaultRuleView<'_> {
    fn rules(&self) -> Result<Vec<Rule>> {
        self.vault.list_rules()
    }
    fn secret_value(&self, key_name: &str) -> Result<Option<String>> {
        Ok(self.secrets.get(key_name).cloned())
    }
}

/// 启动者判定（守护进程侧）：对端 PID → 进程链回溯；失败 → fail-closed
/// `unknown`（授权门第 1 层拒绝）。客户端自报 starter 一律不信任。
fn derive_starter(peer: &PeerInfo) -> String {
    if peer.pid == 0 || !starter::peer_session_ok(peer.pid) {
        return UNKNOWN_STARTER.to_string();
    }
    starter::resolve_starter(peer.pid, starter::platform_table().as_ref())
}

/// 审计来源标注（`authz.evaluate`/`rule.*` 的 `channel` 参数；缺省 cli）。
/// `wsl-bridge` = WSL 内客户端经 interop stdio 桥（cross-subsystem.md §7.5）。
fn audit_channel(channel: Option<&str>) -> AuditChannel {
    match channel {
        Some("desktop") => AuditChannel::Desktop,
        Some("wsl-bridge") => AuditChannel::WslBridge,
        _ => AuditChannel::Cli,
    }
}

/// 阶段① 结果：最终响应（不阻塞）或待审批（等待移出命令锁）。
enum AuthzBegin {
    Final(String),
    Pending {
        request_id: uuid::Uuid,
        expires_at: Instant,
    },
}

/// RpcResponse → 行（序列化失败兜底 `{}`）。
fn rpc_string(resp: RpcResponse) -> String {
    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
}

/// `rule.list` 参数（可选 channel 标注）。
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleListParams {
    #[serde(default)]
    channel: Option<String>,
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

// ---------------------------------------------------------------------------
// 请求 → 响应装配（命令锁 + 无锁特殊路径）
// ---------------------------------------------------------------------------

/// 装配请求处理器：`sync.trigger` 与 `authz.evaluate` 走**命令锁外**执行路径
/// （网络 I/O / 审批等待不阻塞其他命令，G1），其余命令在命令锁内串行。
///
/// 生产（`lk daemon` / 桌面内嵌实例）与测试共用本装配，保证行为一致。
pub fn make_handler(state: &Arc<Mutex<Daemon>>, shared: &Arc<SharedDaemon>) -> transport::Handler {
    let handler_state = Arc::clone(state);
    let handler_shared = Arc::clone(shared);
    Arc::new(move |line: &str, peer: &PeerInfo| -> String {
        // sync.trigger：命令锁外执行轮次（网络 I/O 不阻塞其他命令）
        if let Some(resp) = try_sync_trigger(&handler_state, &handler_shared, line) {
            return resp;
        }
        // authz.evaluate：三阶段（① 命令锁内第 1/2 层 + 登记审批 →
        // ② 锁外等待决策（≤30s）→ ③ 重取锁收尾）；等待期间其他命令照常服务
        if let Some(resp) = try_authz_evaluate(&handler_state, &handler_shared, line, peer) {
            return resp;
        }
        let mut guard = handler_state.lock().expect("daemon mutex poisoned");
        guard.handle(line, peer)
    })
}

/// `authz.evaluate` 的无锁路径（G1 回归：30s 审批等待不持有命令锁）。
///
/// ① 命令锁内：会话预检（含空闲超时检查）+ 启动者判定 + 第 1/2 层短路；
///    需要审批 → 登记待审批 + 广播 `authz.request`；
/// ② 命令锁外：在待审批注册表上等待决策（最多 `approval_timeout_secs`，
///    超时默认拒绝）；
/// ③ 命令锁内：收决策 → 解密 key 值 → 审计（channel=Approval）→ 响应。
pub fn try_authz_evaluate(
    state: &Mutex<Daemon>,
    shared: &SharedDaemon,
    line: &str,
    peer: &PeerInfo,
) -> Option<String> {
    let req: RpcRequest = serde_json::from_str(line).ok()?;
    if req.method != M_AUTHZ_EVALUATE {
        return None;
    }
    let id = req.id.clone();
    let token = extract_token(&req.params);
    // 阶段①：命令锁内
    let begin = {
        let mut guard = state.lock().expect("daemon mutex poisoned");
        guard.auto_lock_if_idle();
        if !guard.trigger_precheck(token.as_deref()) {
            return Some(rpc_string(session_invalid(id)));
        }
        guard.authz_begin(id.clone(), req.params, peer)
    };
    match begin {
        AuthzBegin::Final(resp) => Some(resp),
        AuthzBegin::Pending {
            request_id,
            expires_at,
        } => {
            // 阶段②：锁外等待（不持命令锁；vault/审批注册表短锁除外）
            let decision = shared.approvals.await_decision(request_id);
            let _ = expires_at; // 到期时刻以登记值为准
                                // 阶段③：重取命令锁收尾
            let resp = {
                let mut guard = state.lock().expect("daemon mutex poisoned");
                let r = guard.authz_finalize(id, request_id, decision);
                guard.last_activity = Instant::now();
                r
            };
            Some(resp)
        }
    }
}

// ---------------------------------------------------------------------------
// 守护进程入口（CLI / 桌面内嵌实例共用；决策 #2 A）
// ---------------------------------------------------------------------------

/// 绑定端点 + 装配守护（Daemon::start + 后台同步轮询线程），在后台线程
/// 运行 serve 循环直至 [`global_shutdown`] 置位。
///
/// - CLI（`lk daemon`）：经 [`run`] 调用，绑定失败直接报错退出；
/// - 桌面内嵌（M2 desktop）：进程内起守护线程，**同时 serve 本地 socket 供
///   `lk` CLI 复用**（决策 #2 A）；返回句柄供 tauri command 桥转发
///   JSON-RPC 与订阅推送。
///
/// 返回（守护线程句柄, 命令锁, 跨线程共享态）。
pub type EmbeddedDaemon = (
    std::thread::JoinHandle<i32>,
    Arc<Mutex<Daemon>>,
    Arc<SharedDaemon>,
);

pub fn serve_embedded(dir: &Path) -> std::result::Result<EmbeddedDaemon, String> {
    let bind = transport::bind_server(dir);
    #[cfg(unix)]
    let listener = match bind {
        Ok(l) => l,
        Err(e) => return Err(format!("绑定失败：{e}")),
    };
    #[cfg(windows)]
    if let Err(e) = bind {
        return Err(format!("绑定失败：{e}"));
    }
    let daemon = match Daemon::start(dir) {
        Ok(d) => d,
        Err(e) => return Err(format!("启动失败：{e}")),
    };
    let shared = daemon.shared();
    let state = Arc::new(Mutex::new(daemon));
    // 后台同步轮询线程（M1）：只在解锁态 + 已配置时执行一轮；锁定即停止。
    // 间隔 = 配置值 × 2^风暴等级（封顶 1h）；失败静默（下一轮重试）。
    spawn_sync_poller(Arc::clone(&shared));
    let handler = make_handler(&state, &shared);
    let hub = Some(Arc::clone(&shared.push));
    let serve_state = Arc::clone(&state);
    #[cfg(windows)]
    let serve_dir = dir.to_path_buf();
    let thread = std::thread::Builder::new()
        .name("lk-daemon".into())
        .spawn(move || {
            #[cfg(unix)]
            let result = transport::serve(listener, handler, hub, global_shutdown());
            #[cfg(windows)]
            let result = transport::serve(&serve_dir, handler, hub, global_shutdown());
            // 优雅退出清理：删令牌 + 端点（serve 循环结束后由本线程执行；
            // 桌面端进程退出路径由 lk-app 侧 `shutdown_on_exit` 兜底，双清理幂等）
            if let Ok(mut guard) = serve_state.lock() {
                guard.shutdown();
            }
            match result {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("lk daemon: {e}");
                    1
                }
            }
        })
        .map_err(|e| format!("守护线程启动失败：{e}"))?;
    Ok((thread, state, shared))
}

/// 后台同步轮询线程（解锁态 + 已配置时按风暴退避间隔执行轮次）。
fn spawn_sync_poller(shared: Arc<SharedDaemon>) {
    use lk_core::sync::{next_poll_interval, DEFAULT_SYNC_INTERVAL_SECS};
    let poller = shared;
    std::thread::Builder::new()
        .name("lk-sync-poller".into())
        .spawn(move || {
            let mut next_sleep = DEFAULT_SYNC_INTERVAL_SECS;
            loop {
                std::thread::sleep(std::time::Duration::from_secs(next_sleep));
                {
                    let mut cfg = poller.config.write().unwrap();
                    *cfg = read_config(&poller.dir);
                }
                let (base, enabled, unlocked) = {
                    let cfg = poller.config.read().unwrap();
                    let base = cfg
                        .sync
                        .as_ref()
                        .filter(|c| c.validate().is_ok())
                        .map(|c| c.interval_secs)
                        .unwrap_or(DEFAULT_SYNC_INTERVAL_SECS);
                    (
                        base,
                        cfg.sync.is_some(),
                        poller.vault.read().unwrap().is_some(),
                    )
                };
                if unlocked && enabled {
                    if let Err(e) = run_sync_round(&poller) {
                        eprintln!("lk daemon: 同步失败（下一轮重试）：{}", e.message());
                    }
                    next_sleep =
                        next_poll_interval(base, poller.sync.lock().unwrap().state.storm_level);
                } else {
                    next_sleep = next_poll_interval(base, 0);
                }
            }
        })
        .expect("同步轮询线程可启动");
}

/// 以守护进程方式运行（CLI `lk daemon` 入口）：绑定 → 装配 → 服务直至退出。
/// 返回进程退出码。
pub fn run(dir: &Path) -> i32 {
    eprintln!(
        "lk daemon: 监听于 {}（pid {}）",
        dir.display(),
        std::process::id()
    );
    match serve_embedded(dir) {
        Ok((thread, _state, _shared)) => {
            // 服务直至退出（SIGINT/SIGTERM → serve 循环置位退出）
            thread.join().unwrap_or(1)
        }
        Err(e) => {
            eprintln!("lk daemon: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lk_core::audit::AuditLog;
    use lk_core::bus::{FnSink, SessionVia, VaultEvent};
    use lk_core::crypto::test_kdf_params;
    use lk_core::storage::{GetResult, LocalStorage, PutOutcome, RemoteObject};
    use lk_core::sync::SyncConfig;
    use lk_core::vault::init_vault_with_params;
    use std::sync::mpsc;
    use std::time::Duration;
    use std::time::Instant;

    /// M1.5 事件总线装配回归：守护进程解锁 → `session.unlocked(password)`、
    /// 写条目 → `item.changed`、锁定 → `session.locked(manual)`。
    #[test]
    fn daemon_emits_session_and_item_events_on_bus() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut audit = AuditLog::open(dir.path()).unwrap();
            init_vault_with_params(
                dir.path(),
                "pw123456",
                false,
                &mut audit,
                &test_kdf_params(),
            )
            .unwrap();
        }
        let mut daemon = Daemon::start(dir.path()).unwrap();
        let events = Arc::new(Mutex::new(Vec::new()));
        let e = Arc::clone(&events);
        daemon.core.bus().subscribe(Arc::new(FnSink::new(move |ev| {
            e.lock().unwrap().push(ev.clone());
        })));

        let unlock = rpc_result(&daemon.handle(
            &rpc_line(
                M_VAULT_UNLOCK,
                None,
                json!({ "masterPassword": "pw123456" }),
            ),
            &PeerInfo::unknown(),
        ));
        let token = unlock["token"].as_str().unwrap().to_string();
        daemon.handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "login", "name": "X", "username": "u",
                    "password": "p", "uris": [], "custom": []
                } }),
            ),
            &PeerInfo::unknown(),
        );
        daemon.handle(
            &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );

        let seen = events.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "解锁 + 写条目 + 锁定 = 3 个事件：{seen:?}");
        assert!(matches!(
            &seen[0],
            VaultEvent::SessionUnlocked {
                via: SessionVia::Password
            }
        ));
        match &seen[1] {
            VaultEvent::ItemChanged {
                revision_date,
                kind,
                deleted,
                ..
            } => {
                assert!(!revision_date.is_empty());
                assert_eq!(kind, "login");
                assert!(!deleted);
            }
            other => panic!("第 2 个事件应为 item.changed：{other:?}"),
        }
        assert!(matches!(
            &seen[2],
            VaultEvent::SessionLocked {
                reason: LockReason::Manual
            }
        ));
    }

    /// M2.5 首启检测：`vault.status` 的 `initialized` 标志——无库 = 首启（前端
    /// 据此进初始化向导）；`vault.init` 建库后翻转；`vault.init` 的弱密码/
    /// 已存在均被拒绝（错误码不同，UI 层统一文案不区分，ipc.md §3）。
    #[test]
    fn vault_status_reports_initialized_and_init_policy() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = Daemon::start(dir.path()).unwrap();

        // 无库：initialized=false（首启）
        let resp = daemon.handle(
            &rpc_line(M_VAULT_STATUS, None, json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["initialized"], false);
        assert_eq!(v["result"]["unlocked"], false);

        // 弱主密码（<8 位）→ 拒绝（ERR_WEAK_PASSWORD）
        let resp = daemon.handle(
            &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "short" })),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], ERR_WEAK_PASSWORD);
        assert_eq!(v["error"]["message"], MSG_WEAK_PASSWORD);
        // 弱密码未建库：仍为未初始化
        let resp = daemon.handle(
            &rpc_line(M_VAULT_STATUS, None, json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["initialized"], false);

        // 合法主密码 → 建库 + 恢复码（仅展示一次）+ initialized=true
        let resp = daemon.handle(
            &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "pw123456" })),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["error"].is_null());
        let code = v["result"]["recoveryCode"].as_str().unwrap();
        assert_eq!(code.len(), 5 * 8 + 4, "恢复码 5 组 × 8 字符 + 4 空格");

        // 已存在库 → 再次 init 拒绝（ERR_VAULT_EXISTS；前端统一文案）
        let resp = daemon.handle(
            &rpc_line(M_VAULT_INIT, None, json!({ "masterPassword": "pw123456" })),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], ERR_VAULT_EXISTS);

        // 有库：initialized=true（锁态也可响应，无需令牌）
        let resp = daemon.handle(
            &rpc_line(M_VAULT_STATUS, None, json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["initialized"], true);
        assert_eq!(v["result"]["unlocked"], false);

        // 建库后即可用同一主密码解锁（向导 Step4 = init + unlock 两段）
        let resp = daemon.handle(
            &rpc_line(
                M_VAULT_UNLOCK,
                None,
                json!({ "masterPassword": "pw123456" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["error"].is_null());
        assert!(v["result"]["token"].as_str().unwrap().len() >= 32);
    }

    /// 慢网络后端（G1 回归夹具，同 M1.5）。
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

    /// G1 根治回归（M1.5 既有）：同步轮次进行中（慢网络后端持网络 I/O 窗口），
    /// 前台命令不被阻塞；且轮次应用阶段不覆盖同步期间命令的更新。
    #[test]
    fn sync_round_does_not_block_commands_and_apply_respects_races() {
        let dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        {
            let mut audit = AuditLog::open(dir.path()).unwrap();
            init_vault_with_params(
                dir.path(),
                "pw123456",
                false,
                &mut audit,
                &test_kdf_params(),
            )
            .unwrap();
        }
        let mut daemon = Daemon::start(dir.path()).unwrap();
        let unlock = rpc_result(&daemon.handle(
            &rpc_line(
                M_VAULT_UNLOCK,
                None,
                json!({ "masterPassword": "pw123456" }),
            ),
            &PeerInfo::unknown(),
        ));
        let token = unlock["token"].as_str().unwrap().to_string();
        {
            let cfg = Config {
                auto_lock_minutes: 60,
                sync: Some(SyncConfig {
                    url: "file:///unused".into(),
                    interval_secs: 60,
                }),
                approval_timeout_secs: 30,
            };
            *daemon.shared().config.write().unwrap() = cfg;
        }
        let put_x = rpc_result(&daemon.handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "login", "name": "X", "username": "u1",
                    "password": "p1", "uris": [], "custom": []
                } }),
            ),
            &PeerInfo::unknown(),
        ));
        let x_id = put_x["item"]["id"].as_str().unwrap().to_string();
        let x_rev1 = put_x["item"]["revision"].as_str().unwrap().to_string();
        let shared = daemon.shared();
        run_sync_round_with(
            &shared,
            Box::new(LocalStorage::new(remote_dir.path().to_path_buf())),
        )
        .unwrap();
        // 远端较新 X（rev2）：第二个客户端（同钥拷贝）编辑并同步
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
            let mut b = UnlockedVault::unlock(b_dir.path(), "pw123456").unwrap();
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
        daemon.handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                        "type": "login", "name": "Y", "username": "u2",
                        "password": "p2", "uris": [], "custom": []
                    } }),
            ),
            &PeerInfo::unknown(),
        );
        let (tx, rx) = mpsc::channel();
        let slow = Box::new(SlowBackend {
            inner: LocalStorage::new(remote_dir.path().to_path_buf()),
            delay: Duration::from_millis(400),
            signals: tx,
        });
        let round_shared = Arc::clone(&shared);
        let round = std::thread::spawn(move || run_sync_round_with(&round_shared, slow));

        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let t0 = Instant::now();
        let list = daemon.handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(300),
            "item.list 在同步网络 I/O 中被阻塞 {elapsed:?}"
        );
        assert_eq!(rpc_result(&list)["items"].as_array().unwrap().len(), 2);

        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let put = daemon.handle(
            &rpc_line(
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
            ),
            &PeerInfo::unknown(),
        );
        let put_result = rpc_result(&put);
        assert!(
            put_result["item"]["id"].as_str().is_some(),
            "命令更新在同步网络 I/O 中被阻塞或被拒绝：{put}"
        );

        rx.recv_timeout(Duration::from_secs(5)).unwrap();

        let summary = round.join().unwrap().unwrap();
        assert_eq!(summary.pulled, 0, "应用复核跳过旧快照导入");
        assert_eq!(summary.pushed, 1, "Y 已推送");
        let x = rpc_result(&daemon.handle(
            &rpc_line(M_ITEM_GET, Some(&token), json!({ "id": x_id })),
            &PeerInfo::unknown(),
        ));
        assert_eq!(
            x["username"].as_str().unwrap(),
            "local-race",
            "同步期间命令的更新不被轮次覆盖"
        );
        let status = rpc_result(&daemon.handle(
            &rpc_line(M_VAULT_STATUS, None, json!({})),
            &PeerInfo::unknown(),
        ));
        assert!(status["syncWatermark"].as_str().is_some());
    }

    // ------------------------------------------------------------------
    // M2：授权门（三层短路 / 审批 / G1）/ 规则库 / 推送通道 / 审计
    // ------------------------------------------------------------------

    /// M2 测试夹具：已初始化 + 已解锁的守护进程（命令锁 + 共享态）。
    /// 可选 seed 一个 secret 条目（key 名 → 值）。
    fn m2_daemon(
        dir: &std::path::Path,
        secret: Option<(&str, &str)>,
    ) -> (Arc<Mutex<Daemon>>, Arc<SharedDaemon>, String) {
        {
            let mut audit = AuditLog::open(dir).unwrap();
            init_vault_with_params(dir, "pw123456", false, &mut audit, &test_kdf_params()).unwrap();
        }
        let mut daemon = Daemon::start(dir).unwrap();
        // 审批超时调小（测试不等真实 30s）
        daemon
            .shared()
            .config
            .write()
            .unwrap()
            .approval_timeout_secs = 1;
        let unlock = rpc_result(&daemon.handle(
            &rpc_line(
                M_VAULT_UNLOCK,
                None,
                json!({ "masterPassword": "pw123456" }),
            ),
            &PeerInfo::unknown(),
        ));
        let token = unlock["token"].as_str().unwrap().to_string();
        if let Some((name, value)) = secret {
            daemon.handle(
                &rpc_line(
                    M_ITEM_PUT,
                    Some(&token),
                    json!({ "item": {
                        "type": "secret", "name": name, "value": value,
                        "purpose": "", "expiresAt": null
                    } }),
                ),
                &PeerInfo::unknown(),
            );
        }
        let shared = daemon.shared();
        let state = Arc::new(Mutex::new(daemon));
        (state, shared, token)
    }

    /// 测试用对端：真实 PID + 指定 cwd（授权判定走真实进程链回溯）。
    /// cwd 以 canonical 形态给出（与生产传输层 `resolve_peer_cwd` 一致：
    /// Windows 短名/符号链接须解析，否则与 canonical 规则 projectDir 不匹配）。
    fn test_peer(cwd: Option<&std::path::Path>) -> PeerInfo {
        PeerInfo {
            pid: std::process::id(),
            cwd: cwd.map(|p| {
                std::fs::canonicalize(p)
                    .map(|c| c.to_string_lossy().to_string())
                    .unwrap_or_else(|_| p.to_string_lossy().to_string())
            }),
        }
    }

    /// 审计事件（守护进程审计文件读取）。
    fn audit_events(dir: &std::path::Path) -> Vec<lk_core::audit::AuditEvent> {
        AuditLog::open(dir).unwrap().read().unwrap()
    }

    /// 规则入库形态与运行时 cwd 判定同基准（§7.4 两侧同函数）：rule.add 的
    /// canonicalize 产物再过 canonical_project_dir 入库；Windows 上该归一化
    /// 剥离 verbatim 前缀，否则与 evaluate 侧归一化 cwd 不匹配（回归门：
    /// Windows CI 下此断言直接捕捉存储形态漂移）。
    #[test]
    fn rule_add_stores_normalized_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, _shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let add = rpc_result(&state.lock().unwrap().handle(
            &rpc_line(
                M_RULE_ADD,
                Some(&token),
                json!({ "projectDir": proj.path(), "name": "p",
                        "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "cli" }),
            ),
            &PeerInfo::unknown(),
        ));
        let stored = add["rule"]["projectDir"]
            .as_str()
            .expect("规则应入库")
            .to_string();
        let canonical = lk_core::path_ns::canonical_project_dir(
            &std::fs::canonicalize(proj.path()).unwrap().to_string_lossy(),
        );
        assert_eq!(stored, canonical);
        // 归一化后的存储形态与 evaluate 侧归一化 cwd 祖先匹配命中
        let handler = make_handler(&state, &_shared);
        let peer = test_peer(Some(proj.path()));
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" }),
            ),
            &peer,
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true, "规则命中应放行：{resp}");
    }

    /// 规则命中（第 2 层）：env 只含被授权 key 的值；审计 allowed（channel=cli）。
    #[test]
    fn authz_rule_hit_injects_env_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        // 规则：proj 下 npm * 授权 NPM_TOKEN
        let add = rpc_result(&state.lock().unwrap().handle(
            &rpc_line(
                M_RULE_ADD,
                Some(&token),
                json!({ "projectDir": proj.path(), "name": "publish",
                        "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "cli" }),
            ),
            &PeerInfo::unknown(),
        ));
        assert!(add["rule"]["id"].as_str().is_some());

        let handler = make_handler(&state, &shared);
        let peer = test_peer(Some(proj.path()));
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "cli" }),
            ),
            &peer,
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true, "规则命中应放行：{resp}");
        assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");
        assert!(
            v["result"]["env"].get("GH_TOKEN").is_none(),
            "未授权 key 不可见"
        );
        // 审计：allowed（channel=cli；starter 为真实进程链回溯，非 unknown）
        let events = audit_events(dir.path());
        let authz_evs: Vec<_> = events
            .iter()
            .filter(|e| e.command.starts_with("lk inject"))
            .collect();
        assert_eq!(authz_evs.len(), 1);
        assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);
        assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Cli);
        assert_ne!(authz_evs[0].starter, lk_core::starter::UNKNOWN_STARTER);
        assert_eq!(authz_evs[0].target, "npm");
        assert!(
            !serde_json::to_string(authz_evs[0])
                .unwrap()
                .contains("sekrit"),
            "审计不含密钥值"
        );
    }

    /// 第 1 层：启动者未知（对端 PID 不可得）→ 拒绝 + 审计；不弹窗。
    #[test]
    fn authz_denies_unknown_starter_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
            ),
            &PeerInfo::unknown(), // pid=0 → starter=unknown
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], false);
        assert_eq!(v["result"]["reason"], "unknown_starter");
        let authz_evs: Vec<_> = audit_events(dir.path())
            .into_iter()
            .filter(|e| e.command.starts_with("lk inject"))
            .collect();
        assert_eq!(authz_evs.len(), 1);
        assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Denied);
    }

    /// 伪造 cwd（客户端自报参数）→ 守护进程以对端真实 cwd 判定：
    /// 参数指向有规则的项目目录、真实 cwd 在别处 → 拒绝（testing.md #2）。
    #[test]
    fn authz_ignores_client_cwd_and_uses_peer_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        state.lock().unwrap().handle(
            &rpc_line(
                M_RULE_ADD,
                Some(&token),
                json!({ "projectDir": proj.path(), "name": "p",
                        "command": "npm *", "keys": ["NPM_TOKEN"] }),
            ),
            &PeerInfo::unknown(),
        );
        let handler = make_handler(&state, &shared);
        // 客户端自报 cwd = 项目目录（伪造）；真实 cwd = other → 必须拒绝
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"],
                        "cwd": proj.path() }),
            ),
            &test_peer(Some(other.path())),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], false, "伪造 cwd 不得放行：{resp}");
        // 真实 cwd = 项目目录 → 放行
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"] }),
            ),
            &test_peer(Some(proj.path())),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true);
    }

    /// 无审批界面（无订阅连接）+ 未命中规则 → 立即拒绝（不阻塞），
    /// 原因 no_ui + 审计 denied（testing.md #7）。
    #[test]
    fn authz_denies_without_ui_fast() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        assert_eq!(shared.push.subscriber_count(), 0);
        let t0 = Instant::now();
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
            ),
            &test_peer(Some(proj.path())),
        );
        assert!(
            t0.elapsed() < Duration::from_millis(300),
            "无界面必须立即拒绝"
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], false);
        assert_eq!(v["result"]["reason"], "no_ui");
    }

    /// 第 3 层完整闭环：订阅连接存在 → evaluate 阻塞等审批 →
    /// 广播 authz.request 帧 → approval.result 回传 → 放行 + 审计(Approval)。
    #[test]
    fn authz_approval_roundtrip_via_push_and_result() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        // 订阅连接（桌面壳模拟）
        let (_sid, rx) = shared.push.subscribe();
        assert_eq!(shared.push.subscriber_count(), 1);
        // 线程内发起 evaluate（阻塞至审批回传）
        let peer = test_peer(Some(proj.path()));
        let line = rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"], "channel": "desktop" }),
        );
        let h = std::thread::spawn({
            let handler = handler.clone();
            let peer = peer.clone();
            move || handler(&line, &peer)
        });
        // 推送通道收到 authz.request 帧（含 requestId；无密钥值）
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["method"], "authz.request");
        assert!(fv.get("id").is_none());
        assert_eq!(
            fv["params"]["projectDir"],
            std::fs::canonicalize(proj.path())
                .unwrap()
                .to_string_lossy()
                .to_string()
        );
        assert_eq!(fv["params"]["command"], "yarn publish");
        assert_eq!(fv["params"]["keys"][0], "NPM_TOKEN");
        assert!(!frame.contains("sekrit"), "authz.request 不含密钥值");
        let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
        // 审批回传（approval.result；走常规请求连接）
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_APPROVAL_RESULT,
                Some(&token),
                json!({ "requestId": request_id, "decision": "allowed" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["accepted"], true);
        // evaluate 返回放行 + env
        let resp = h.join().unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true);
        assert_eq!(v["result"]["env"]["NPM_TOKEN"], "sekrit");
        // 审计：channel=Approval（第 3 层结果）
        let authz_evs: Vec<_> = audit_events(dir.path())
            .into_iter()
            .filter(|e| e.command.starts_with("lk inject"))
            .collect();
        assert_eq!(authz_evs.len(), 1);
        assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
        assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Allowed);
    }

    /// 审批超时 → 默认拒绝 + 审计 timeout（channel=Approval）。
    #[test]
    fn authz_approval_timeout_denies_and_audits() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        let (_sid, rx) = shared.push.subscribe();
        let peer = test_peer(Some(proj.path()));
        let line = rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
        );
        let h = std::thread::spawn({
            let handler = handler.clone();
            let peer = peer.clone();
            move || handler(&line, &peer)
        });
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
        // 不回传 → 1s 后超时默认拒绝
        let resp = h.join().unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], false);
        assert_eq!(v["result"]["reason"], "timeout");
        // 超时后回传 → 忽略（条目已清理）
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_APPROVAL_RESULT,
                Some(&token),
                json!({ "requestId": request_id, "decision": "allowed" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["accepted"], false);
        let authz_evs: Vec<_> = audit_events(dir.path())
            .into_iter()
            .filter(|e| e.command.starts_with("lk inject"))
            .collect();
        assert_eq!(authz_evs.len(), 1);
        assert_eq!(authz_evs[0].result, lk_core::audit::AuditResult::Timeout);
        assert_eq!(authz_evs[0].channel, lk_core::audit::AuditChannel::Approval);
    }

    /// G1 回归：authz.evaluate 在第 3 层等待审批期间，其他命令不被阻塞
    /// （30s 等待不持命令锁）。
    #[test]
    fn authz_wait_does_not_block_other_commands() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        let (_sid, rx) = shared.push.subscribe();
        // 发起 evaluate（阻塞等待审批）
        let line = rpc_line(
            M_AUTHZ_EVALUATE,
            Some(&token),
            json!({ "command": "yarn publish", "keys": ["NPM_TOKEN"] }),
        );
        let peer = test_peer(Some(proj.path()));
        let h = std::thread::spawn({
            let handler = handler.clone();
            let peer = peer.clone();
            move || handler(&line, &peer)
        });
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        let request_id = fv["params"]["requestId"].as_str().unwrap().to_string();
        // 等待期间：其他命令必须及时返回（命令锁未被 30s 等待占用）
        let t0 = Instant::now();
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_ITEM_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "审批等待期间命令被阻塞 {elapsed:?}"
        );
        assert!(rpc_result(&resp)["items"].as_array().is_some());
        // 回传 → evaluate 完成
        shared.approvals.resolve(
            uuid::Uuid::parse_str(&request_id).unwrap(),
            ApprovalDecision::Allowed,
        );
        let resp = h.join().unwrap();
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true);
    }

    /// 规则 CRUD（IPC）+ 审计（channel 区分）+ `item.changed(kind="rule")` 广播。
    #[test]
    fn rule_crud_audits_and_broadcasts() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), None);
        // 监听 item.changed 帧（推送通道）
        let (_sid, rx) = shared.push.subscribe();
        // add
        let add = state.lock().unwrap().handle(
            &rpc_line(
                M_RULE_ADD,
                Some(&token),
                json!({ "projectDir": proj.path(), "name": "pub",
                        "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "desktop" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&add).unwrap();
        let rule = &v["result"]["rule"];
        let id = rule["id"].as_str().unwrap().to_string();
        assert_eq!(rule["name"], "pub");
        assert_eq!(rule["command"], "npm publish");
        // projectDir 以 canonical 形态入库（Windows 下含 \\?\ 前缀与短名展开）
        let canonical_proj = std::fs::canonicalize(proj.path())
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(rule["projectDir"], canonical_proj);
        // 广播 item.changed(kind=rule, deleted=false)（决策 #6）
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["method"], "item.changed");
        assert_eq!(fv["params"]["type"], "rule");
        assert_eq!(fv["params"]["deleted"], false);
        assert_eq!(fv["params"]["itemId"], id);
        // list
        let list = state.lock().unwrap().handle(
            &rpc_line(M_RULE_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&list).unwrap();
        assert_eq!(v["result"]["rules"].as_array().unwrap().len(), 1);
        // remove → 广播 deleted=true
        state.lock().unwrap().handle(
            &rpc_line(M_RULE_REMOVE, Some(&token), json!({ "id": id })),
            &PeerInfo::unknown(),
        );
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["params"]["type"], "rule");
        assert_eq!(fv["params"]["deleted"], true);
        // list 不再包含
        let list = state.lock().unwrap().handle(
            &rpc_line(M_RULE_LIST, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&list).unwrap();
        assert_eq!(v["result"]["rules"].as_array().unwrap().len(), 0);
        // 审计：add（desktop）/ list ×2（cli）/ remove（cli）四条留痕
        let events = audit_events(dir.path());
        let rule_evs: Vec<_> = events
            .iter()
            .filter(|e| e.command.starts_with("rule."))
            .collect();
        assert_eq!(rule_evs.len(), 4);
        assert_eq!(rule_evs[0].command, "rule.add pub");
        assert_eq!(rule_evs[0].channel, lk_core::audit::AuditChannel::Desktop);
        assert_eq!(
            rule_evs.iter().filter(|e| e.command == "rule.list").count(),
            2
        );
        assert!(rule_evs
            .iter()
            .any(|e| e.command.starts_with("rule.remove")));
    }

    /// rule.add 校验：超长/非法 projectDir、非法 key 名 → 拒绝不入库（#19）。
    #[test]
    fn rule_add_rejects_invalid_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _shared, token) = m2_daemon(dir.path(), None);
        let handle = |params: Value| -> Value {
            let resp = state.lock().unwrap().handle(
                &rpc_line(M_RULE_ADD, Some(&token), params),
                &PeerInfo::unknown(),
            );
            serde_json::from_str(&resp).unwrap()
        };
        // 相对路径
        assert!(handle(
            json!({ "projectDir": "relative/path", "name": "n", "command": "c", "keys": ["K"] })
        )["error"]
            .is_object());
        // 不存在的绝对路径
        assert!(handle(json!({ "projectDir": "/definitely/not/exists-xyz", "name": "n", "command": "c", "keys": ["K"] }))["error"].is_object());
        // 非法 key 名
        assert!(handle(json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": ["BAD-KEY!"] }))["error"].is_object());
        // 超长 command
        let long = "x".repeat(1025);
        assert!(handle(json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": long, "keys": ["K"] }))["error"].is_object());
        // 空 keys
        assert!(handle(
            json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": [] })
        )["error"]
            .is_object());
        // 合法 → 入库
        assert!(handle(json!({ "projectDir": std::env::temp_dir(), "name": "n", "command": "c", "keys": ["K"] }))["result"]["rule"]["id"].is_string());
    }

    /// 跨命名空间归一化（cross-subsystem.md §7.4/§10）：rule.add 收 UNC WSL
    /// 路径 → 以 `wsl://<distro>/<rest>` 规范形入库；运行时对端 cwd 为伪造
    /// 写法变体（大写 distro / 尾斜杠）→ 归一化后与规则一致匹配放行；
    /// `channel=wsl-bridge` 如实审计。
    #[test]
    fn rule_add_and_authz_normalize_wsl_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        // 规则入库：UNC 形态（守护进程侧归一化为规范形）
        let raw = state.lock().unwrap().handle(
            &rpc_line(
                M_RULE_ADD,
                Some(&token),
                json!({ "projectDir": r"\\wsl.localhost\Debian\home\u\p", "name": "wsl",
                        "command": "npm *", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
            ),
            &PeerInfo::unknown(),
        );
        let add = rpc_result(&raw);
        assert_eq!(
            add["rule"]["projectDir"], "wsl://Debian/home/u/p",
            "UNC 应归一为 wsl:// 规范形入库：{add}"
        );
        // 运行时：对端 cwd 为伪造写法变体（大写 distro + 尾斜杠）→ 命中同一规则
        let handler = make_handler(&state, &shared);
        let peer = PeerInfo {
            pid: std::process::id(),
            cwd: Some(r"\\wsl.localhost\DEBIAN\home\u\p\".to_string()),
        };
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["NPM_TOKEN"], "channel": "wsl-bridge" }),
            ),
            &peer,
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], true, "归一化后应命中规则：{resp}");
        // 审计如实记录 channel=wsl-bridge
        let authz_evs: Vec<_> = audit_events(dir.path())
            .into_iter()
            .filter(|e| e.command.starts_with("lk inject"))
            .collect();
        assert_eq!(authz_evs.len(), 1);
        assert_eq!(
            authz_evs[0].channel,
            lk_core::audit::AuditChannel::WslBridge
        );
    }

    /// 审批回传伪造 requestId → 忽略（accepted=false；#17）；无令牌 → session.invalid（#18）。
    #[test]
    fn approval_result_rejects_forged_and_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _shared, token) = m2_daemon(dir.path(), None);
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_APPROVAL_RESULT,
                Some(&token),
                json!({ "requestId": uuid::Uuid::new_v4(), "decision": "allowed" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["accepted"], false);
        // 无令牌
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_APPROVAL_RESULT,
                None,
                json!({ "requestId": uuid::Uuid::new_v4(), "decision": "allowed" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["message"], MSG_SESSION_INVALID);
        // 非法 decision
        let resp = state.lock().unwrap().handle(
            &rpc_line(
                M_APPROVAL_RESULT,
                Some(&token),
                json!({ "requestId": uuid::Uuid::new_v4(), "decision": "maybe" }),
            ),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["code"], ERR_INVALID_PARAMS);
    }

    /// 订阅校验：错令牌 → session.invalid（连接不转流模式）。
    #[test]
    fn subscribe_requires_valid_token() {
        let dir = tempfile::tempdir().unwrap();
        let (state, _shared, token) = m2_daemon(dir.path(), None);
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_SUBSCRIBE, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert!(v["result"].is_object());
        let resp = state.lock().unwrap().handle(
            &rpc_line(M_SUBSCRIBE, None, json!({})),
            &PeerInfo::unknown(),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["error"]["message"], MSG_SESSION_INVALID);
    }

    /// 请求的 key 无法解析（不存在）→ 第 1 层拒绝（missing_keys；不弹窗）。
    #[test]
    fn authz_denies_unresolvable_requested_keys() {
        let dir = tempfile::tempdir().unwrap();
        let proj = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), Some(("NPM_TOKEN", "sekrit")));
        let handler = make_handler(&state, &shared);
        let resp = handler(
            &rpc_line(
                M_AUTHZ_EVALUATE,
                Some(&token),
                json!({ "command": "npm publish", "keys": ["GHOST_KEY"] }),
            ),
            &test_peer(Some(proj.path())),
        );
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["allowed"], false);
        assert_eq!(v["result"]["reason"], "missing_keys");
    }

    /// 推送通道：解锁/写条目/锁定 → session.*/item.changed 通知帧（非阻塞）。
    #[test]
    fn push_channel_notifies_session_and_item_events() {
        let dir = tempfile::tempdir().unwrap();
        let (state, shared, token) = m2_daemon(dir.path(), None);
        let (_sid, rx) = shared.push.subscribe();
        // 写条目 → item.changed 帧
        state.lock().unwrap().handle(
            &rpc_line(
                M_ITEM_PUT,
                Some(&token),
                json!({ "item": {
                    "type": "login", "name": "X", "username": "u",
                    "password": "p", "uris": [], "custom": []
                } }),
            ),
            &PeerInfo::unknown(),
        );
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["method"], "item.changed");
        assert_eq!(fv["params"]["type"], "login");
        // 锁定 → session.locked 帧
        state.lock().unwrap().handle(
            &rpc_line(M_VAULT_LOCK, Some(&token), json!({})),
            &PeerInfo::unknown(),
        );
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["method"], "session.locked");
        assert_eq!(fv["params"]["reason"], "manual");
        // 重新解锁 → session.unlocked 帧（旧订阅连接保持有效）
        state.lock().unwrap().handle(
            &rpc_line(
                M_VAULT_UNLOCK,
                None,
                json!({ "masterPassword": "pw123456" }),
            ),
            &PeerInfo::unknown(),
        );
        let frame = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let fv: Value = serde_json::from_str(&frame).unwrap();
        assert_eq!(fv["method"], "session.unlocked");
        assert_eq!(fv["params"]["via"], "password");
        assert!(shared.push.subscriber_count() >= 1);
    }
}
