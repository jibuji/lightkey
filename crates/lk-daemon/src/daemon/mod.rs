//! C 层守护进程宿主核心：状态机（[`Daemon`] / [`SharedDaemon`]）+ RPC 分发 +
//! 装配辅助。执行计划路由见 [`crate::router`]；生命周期入口见 [`lifecycle`]。
//!
//! 子模块为命令域处理组（子模块可见父模块私有字段，无需 pub(crate) 化）；
//! 对外路径经 [`crate`] 再导出保持不变。

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use lk_core::audit::{AuditChannel, AuditLog, AuditResult, EventInput};
use lk_core::audit_anchor::{AnchorCheck, CompositeAuditAnchor};
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

use crate::config::{Config, SyncRuntime};
use crate::notifier::Notifier;
use crate::router::{strategy_of, ExecutionStrategy};
use crate::transport::{PeerInfo, PeerOrigin, PushHub};

use self::authz::AuthzBegin;
use self::lifecycle::{install_shutdown_handlers, load_config};

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
    /// 审计锚点（issue #75）：平台 keychain + 侧写降级；文件外可信锚点。
    anchor: Arc<CompositeAuditAnchor>,
    /// 锚点状态（供 `vault.status.auditAnchorOk`）：平台级锚点可用**且**链未被
    /// 截断 = true。降级到侧写（平台 keychain 不可用）、锚点缺失或检测到截断
    /// = false——桌面 UI 据此提示「审计链可能被截断/防篡改能力减弱」
    /// （`ipc::StatusResult.audit_anchor_ok` 同语义；降级单独由
    /// `audit.verify.anchorDegraded` 细粒度暴露）。
    anchor_ok: std::sync::atomic::AtomicBool,
    /// 组合锚点当前是否处于降级（平台 keychain 不可用）——`vault.status` 可选。
    anchor_degraded: std::sync::atomic::AtomicBool,
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
        let anchor = crate::audit_anchor::make_audit_anchor(&dir);
        let config = load_config(&dir);
        let sync = SyncRuntime::load(&dir);
        install_shutdown_handlers();
        let core = CoreServices::new();
        let sessions = core.new_session();
        // M2 装配：待审批注册表 + 推送通道 + 本地审批通道 + 通知桥
        // （通知桥订阅总线：Rust 事件 → notification 帧 → 订阅连接，非阻塞）
        let approvals = Arc::new(PendingApprovals::new());
        let push = PushHub::new();
        // #72/#78 方案 A：`has_ui` 只数**桌面来源**订阅者——socket 订阅者
        // （任何持令牌进程可建立）不算「有界面」；审批挑战帧也只投给桌面
        // 订阅者（notifier），双重收紧第 3 层的信任前提。
        let approval: Arc<dyn ApprovalChannel> = Arc::new(LocalApprovalChannel::new(
            Arc::clone(&approvals),
            Arc::clone(core.bus()),
            Box::new({
                let push = Arc::clone(&push);
                move || push.desktop_subscriber_count() > 0
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
        let daemon = Daemon {
            sessions,
            audit,
            anchor,
            anchor_ok: std::sync::atomic::AtomicBool::new(false),
            anchor_degraded: std::sync::atomic::AtomicBool::new(false),
            unlock_guard: AuthGuard::default(),
            recover_guard: AuthGuard::default(),
            last_activity: Instant::now(),
            shared,
            core,
            gate,
            pending_authz: Mutex::new(HashMap::new()),
        };
        // 启动自检：锚点 vs 链（截断检测，无需 K_audit），置 `anchor_ok`。
        daemon.anchor_selfcheck();
        Ok(daemon)
    }

    /// 启动自检：锚点 vs 链（截断检测）＋降级状态，置 `anchor_ok`/`anchor_degraded`。
    /// 锁定态也能跑（只读链尾 ordinal/hmac + 组合锚点读取，不需要 K_audit）。
    pub(crate) fn anchor_selfcheck(&self) {
        let clean = self.anchor_continues_clean();
        let degraded = self.anchor.degraded();
        self.anchor_degraded
            .store(degraded, std::sync::atomic::Ordering::Relaxed);
        // 降级到侧写（平台不可用）也计为不 ok：`vault.status.auditAnchorOk`
        // 的唯一告警通道（嵌入式 daemon 的 stderr 用户不可见）。
        self.anchor_ok
            .store(clean && !degraded, std::sync::atomic::Ordering::Relaxed);
    }

    /// 判断当前链相对锚点是否未被截断（锚点缺失也计为不 ok：
    /// 「截断可证明」语义下无法证明 → 报不安全，UI 据此告警）。
    fn anchor_continues_clean(&self) -> bool {
        let events = match self.audit.read() {
            Ok(e) => e,
            Err(_) => return false,
        };
        let ordinal = events.len() as u64;
        let last_hmac = events.last().map(|e| e.hmac.clone()).unwrap_or_default();
        let anchor = match self.anchor.load() {
            Ok(a) => a,
            Err(_) => return false,
        };
        matches!(
            lk_core::audit_anchor::check_anchor(ordinal, &last_hmac, anchor.as_ref()),
            AnchorCheck::Ok | AnchorCheck::AnchorBehind(_)
        )
    }

    /// 同步写锚点（读链尾 → 写组合锚点）。返回是否降级（`Ok(true)` = 平台不可用、
    /// 已落到侧写文件）。**调用方不得持有 vault 写锁**（本方法含同步 I/O：
    /// 读审计文件 + keyring 写入，G1 锁纪律）。锚点写入失败**不阻断**调用方
    /// （fail-open）：只降 degraded 状态、记日志、向调用方返回错误。
    pub(crate) fn sync_anchor(
        &self,
        warn_degraded: bool,
    ) -> std::result::Result<bool, lk_core::audit_anchor::AuditAnchorError> {
        // 读链尾：锁定态 / 解锁态均可（不依赖 K_audit）
        let events = match self.audit.read() {
            Ok(e) => e,
            Err(e) => {
                self.anchor_degraded
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                self.anchor_ok
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                return Err(lk_core::audit_anchor::AuditAnchorError::Io(e.to_string()));
            }
        };
        let value = lk_core::audit_anchor::anchor_from_chain(&events);
        let degraded = self.anchor.store(&value)?;
        self.anchor_degraded
            .store(degraded, std::sync::atomic::Ordering::Relaxed);
        // 写入后链 = 锚点，理应一致；降级（平台不可用）时 anchor_ok = false，
        // 由 status 暴露「防篡改能力减弱」告警（ipc.rs `audit_anchor_ok` 语义）。
        self.anchor_ok
            .store(!degraded, std::sync::atomic::Ordering::Relaxed);
        if degraded && warn_degraded {
            eprintln!(
                "lk daemon: 警告：平台 keychain 不可用，审计锚点已降级到数据目录侧写文件（{}）；防篡改能力减弱（issue #75）",
                self.anchor_sidecar_display()
            );
        }
        Ok(degraded)
    }

    fn anchor_sidecar_display(&self) -> String {
        // 诊断/文案用：侧写路径
        self.shared
            .dir
            .join(lk_core::audit_anchor::AUDIT_ANCHOR_SIDECAR)
            .display()
            .to_string()
    }

    /// 当前锚点状态读取（`vault.status` / 诊断）。
    pub(crate) fn anchor_status(&self) -> (bool, bool) {
        (
            self.anchor_ok.load(std::sync::atomic::Ordering::Relaxed),
            self.anchor_degraded
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    /// 组件锚点引用（后台 flush 线程用）。
    pub(crate) fn anchor(&self) -> Arc<CompositeAuditAnchor> {
        Arc::clone(&self.anchor)
    }

    /// 注入测试锚点（`lk-lib` 集成测试夹具：替换平台/侧写组合为可控 fake）。
    /// 生产路径不调用；替换后立即自检更新 `anchor_ok`。
    #[cfg(test)]
    pub(crate) fn set_anchor(&mut self, anchor: Arc<CompositeAuditAnchor>) {
        self.anchor = anchor;
        self.anchor_selfcheck();
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

    fn dispatch(&mut self, req: RpcRequest, peer: &PeerInfo) -> String {
        let id = req.id.clone();
        let method = req.method.clone();
        let params = req.params;
        let token = extract_token(&params);

        // 空闲超时自动锁定（任何请求都会触发检查）
        self.auto_lock_if_idle();

        // 执行计划路由（ADR-0001）：直调形态查同一张策略表——两阶段策略在
        // 持锁前提下顺序执行与 route() 相同的 phase 方法（单线程直调下锁
        // 窗口不可观察，请求/响应与主缝一致）。
        if strategy_of(&method) == ExecutionStrategy::ApprovalDeferred {
            if !self.trigger_precheck(token.as_deref()) {
                return rpc_string(session_invalid(id));
            }
            let resp = match self.authz_begin(id.clone(), params, peer) {
                AuthzBegin::Final(resp) => resp,
                AuthzBegin::Pending { request_id, .. } => {
                    let decision = self.shared.approvals.await_decision(request_id);
                    let r = self.authz_finalize(id.clone(), request_id, decision);
                    self.touch_activity();
                    r
                }
            };
            return resp;
        }

        // 调用方归因（#66）：Inline 方法派生一次，供写审计的处理器复用
        // （非审计方法不消费；CLI 单发进程语义下多一次进程链回溯成本可
        // 忽略，desktop 直调短路为常量）。
        let caller = CallerId::of(peer);

        let resp = match method.as_str() {
            M_VAULT_STATUS => self.vault_status(id.clone()),
            M_VAULT_INIT => self.vault_init(id.clone(), params, &caller),
            M_VAULT_UNLOCK => self.vault_unlock(id.clone(), params, &caller),
            M_VAULT_LOCK => self.vault_lock(id.clone(), &caller),
            M_VAULT_RECOVER => self.vault_recover(id.clone(), params, &caller),
            M_ITEM_LIST => {
                self.require_session(id.clone(), token, |me| me.item_list(id.clone(), &caller))
            }
            M_ITEM_GET => self.require_session(id.clone(), token, |me| {
                me.item_get(id.clone(), params, &caller)
            }),
            M_ITEM_PUT => self.require_session(id.clone(), token, |me| {
                me.item_put(id.clone(), params, &caller)
            }),
            M_ITEM_DELETE => self.require_session(id.clone(), token, |me| {
                me.item_delete(id.clone(), params, &caller)
            }),
            M_ITEM_EXPORT => self.require_session(id.clone(), token, |me| {
                me.item_export(id.clone(), params, &caller)
            }),
            M_AUDIT_LIST => self.require_session(id.clone(), token, |me| {
                me.audit_list(id.clone(), params, &caller)
            }),
            M_AUDIT_VERIFY => {
                self.require_session(id.clone(), token, |me| me.audit_verify(id.clone()))
            }
            // OutsideLock 策略的直调形态：持锁跑同一轮次（route() 的主缝
            // 形态在命令锁外执行；此处单线程等价，请求/响应一致）
            M_SYNC_TRIGGER => {
                self.require_session(id.clone(), token, |me| me.sync_trigger_inline(id.clone()))
            }
            M_SYNC_POLL => self.require_session(id.clone(), token, |me| me.sync_poll(id.clone())),
            // M2：通知订阅（连接转入流模式由传输层处理；此处只做会话校验）。
            // socket 订阅仍可收 item.changed 等事件，但 `has_ui` 不计、
            // 也收不到 authz.request 挑战帧（#72/#78，见 PushHub/Notifier）
            M_SUBSCRIBE => self.require_session(id.clone(), token, |me| me.subscribe(id.clone())),
            M_APPROVAL_RESULT => {
                // #72/#78 方案 A：审批回传仅接受桌面内嵌直调——socket 连接
                // 一律拒绝（专用错误码），「持令牌进程自我批准」路径闭合。
                // 被拒提交写审计（#78：谁在尝试自我批准可归因——starter/channel
                // 取对端归因；已锁定无法签名则跳过，与桌面路径失败提交同口径）
                if peer.origin != PeerOrigin::Desktop {
                    let vault = self.shared.vault.read().unwrap();
                    if let Some(v) = vault.as_ref() {
                        let _ = self.audit.append(
                            v.keys(),
                            &caller.event("approval.result", AuditResult::Denied),
                        );
                    }
                    RpcResponse::err(
                        id.clone(),
                        ERR_CHANNEL_FORBIDDEN,
                        MSG_CHANNEL_FORBIDDEN,
                        None,
                    )
                } else {
                    self.require_session(id.clone(), token, |me| {
                        me.approval_result(id.clone(), params, &caller)
                    })
                }
            }
            M_RULE_ADD => self.require_session(id.clone(), token, |me| {
                me.rule_add(id.clone(), params, &caller)
            }),
            M_RULE_LIST => self.require_session(id.clone(), token, |me| {
                me.rule_list(id.clone(), params, &caller)
            }),
            M_RULE_REMOVE => self.require_session(id.clone(), token, |me| {
                me.rule_remove(id.clone(), params, &caller)
            }),
            // authz.evaluate = ApprovalDeferred 策略（见 dispatch 开头的策略
            // 分派；此臂仅为表完整性兜底，正常不会到达）
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

// -------------------------------------------------------------------------
// 装配辅助（分发与授权门共用）
// -------------------------------------------------------------------------

/// 启动者判定（守护进程侧）：对端 PID → 进程链回溯；失败 → fail-closed
/// `unknown`（授权门第 1 层拒绝）。客户端自报 starter 一律不信任。
fn derive_starter(peer: &PeerInfo) -> String {
    if peer.pid == 0 || !starter::peer_session_ok(peer.pid) {
        return UNKNOWN_STARTER.to_string();
    }
    starter::resolve_starter(peer.pid, starter::platform_table().as_ref())
}

/// 单次请求的调用方归因（#66：审计 starter/channel 不再硬编码 "lk"/cli）。
/// dispatch 层派生一次，各命令处理器写入审计事件复用：
///
/// - socket 客户端（CLI / bridge）：starter = 真实进程链回溯结果
///   （bridge 对端回溯出 interop 链顶层，可区分本地 CLI 与桥接调用），
///   回溯失败如实记 `unknown`；channel = cli；
/// - 桌面内嵌直调（lk-app command 桥，无 IPC 对端）：starter/channel =
///   `desktop`（授权路径不看这里——authz.evaluate 仍走 derive_starter，
///   desktop 对端 pid=0 照样 fail-closed）。
pub(crate) struct CallerId {
    pub starter: String,
    pub channel: AuditChannel,
}

impl CallerId {
    /// 按对端来源派生调用方归因。
    fn of(peer: &PeerInfo) -> CallerId {
        match peer.origin {
            crate::transport::PeerOrigin::Desktop => CallerId::desktop_self(),
            crate::transport::PeerOrigin::Socket => CallerId {
                starter: derive_starter(peer),
                channel: peer_channel(peer),
            },
        }
    }

    /// 桌面内嵌直调（command 桥 / 锁屏等进程内路径）。
    fn desktop_self() -> CallerId {
        CallerId {
            starter: "desktop".to_string(),
            channel: AuditChannel::Desktop,
        }
    }

    /// 守护进程自身触发（空闲超时等；channel 无独立 daemon 枚举，沿用 cli，
    /// 靠 starter=daemon 区分——audit.md §2）。
    fn daemon_self() -> CallerId {
        CallerId {
            starter: "daemon".to_string(),
            channel: AuditChannel::Cli,
        }
    }

    /// 以本归因构造常规审计事件（target 恒为 daemon；与 `EventInput::new`
    /// 同字段集，仅 starter/channel 换真实值）。
    fn event(&self, command: impl Into<String>, result: AuditResult) -> EventInput {
        EventInput {
            starter: self.starter.clone(),
            target: "daemon".to_string(),
            command: command.into(),
            result,
            channel: self.channel,
            old_key_id: None,
            new_key_id: None,
        }
    }
}

/// 审计来源标注（`authz.evaluate`/`rule.*` 的 `channel` 参数；缺省按对端
/// 来源，见 [`CallerId`]）。`wsl-bridge` = WSL 内客户端经 interop stdio 桥
/// （cross-subsystem.md §7.5）。
fn audit_channel(channel: &str) -> AuditChannel {
    match channel {
        "desktop" => AuditChannel::Desktop,
        "wsl-bridge" => AuditChannel::WslBridge,
        _ => AuditChannel::Cli,
    }
}

/// 按对端来源的审计通道（#66）：socket 客户端 = cli，桌面内嵌直调 =
/// desktop。只取通道枚举、不做进程链回溯（供缺省回退复用，与
/// [`CallerId::of`] 同口径）。
fn peer_channel(peer: &PeerInfo) -> AuditChannel {
    match peer.origin {
        PeerOrigin::Desktop => AuditChannel::Desktop,
        PeerOrigin::Socket => AuditChannel::Cli,
    }
}

/// 客户端自报 `channel` 标注（参数优先）→ 缺省按对端来源回退
/// （`authz.evaluate` / `rule.*` 共用；audit.md §2）。
fn client_channel(channel: Option<&str>, fallback: AuditChannel) -> AuditChannel {
    channel.map(audit_channel).unwrap_or(fallback)
}

/// RpcResponse → 行（序列化失败兜底 `{}`）。
pub(crate) fn rpc_string(resp: RpcResponse) -> String {
    serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
}

pub(crate) fn extract_token(params: &Value) -> Option<Vec<u8>> {
    params
        .get("token")
        .and_then(|t| t.as_str())
        .and_then(|s| hex::decode(s.trim()).ok())
}

pub(crate) mod authz;
mod items;
pub(crate) mod lifecycle;
mod rules;
mod session;
mod sync_cmds;
mod vault_cmds;
