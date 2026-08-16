//! A/B 层 trait 服务 + C 层装配（模拟 Cordis 语义，`docs/plugin-architecture.md` §3/§4）。
//!
//! 插件化改造是**边界重组 + 声明式装配**，不改变既有安全模型、密文格式、
//! 存储布局（行为不回归，见 `docs/milestones.md` M1.5 出口）。本模块是
//! Rust 侧的插件边界层：
//!
//! - **A 层数据平面**（安全核心，留在 Rust）：[`CryptoService`]（crypto）·
//!   [`VaultStoreService`]（vault-store）· [`RecoveryService`]（recovery）·
//!   [`AuditService`]（audit）· [`SessionService`]（session）。
//! - **B 层能力域**：[`StorageBackend`](crate::storage::StorageBackend)
//!   （storage-backend，本就是可插拔 trait：webdav/s3/local 三实现按配置
//!   切换，对应 D 层 `ctx.isolate` 的「服务换实现」）· [`SyncEngineService`]
//!   （sync-engine，注入 vault-store + storage-backend）。
//! - **C 层装配**：[`CoreServices`]（事件总线 + 无状态地基服务的宿主侧装配点；
//!   lk-cli 的 daemon 用它装配 A/B，见 `crates/lk-cli/src/daemon`）。
//!
//! 注入方向 = 上层注入下层（§4.1）：`sync-engine` 注入 `vault-store` 与
//! `storage-backend`（引擎构造持 `&dyn StorageBackend`，写侧消费
//! `UnlockedVault` 的 crate 内部 `import_*`/`hard_delete` 通道）；`recovery`
//! 注入 `crypto`（信封构建/打开经 KDF + AEAD）；`audit` 注入 `crypto`（HMAC）。
//!
//! 有状态的数据平面服务（vault-store / session / audit）由宿主持有状态、
//! 经事件总线（[`bus`]）解耦：vault-store 写成功 → `item.changed`；session
//! 签发/失效 → `session.unlocked` / `session.locked`。订阅方须**非阻塞**
//! （观察广播，见 [`bus::EventBus`]）。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditEvent, AuditLog, EventInput};
use crate::bus::{EventBus, EventSink, LockReason, SessionVia, VaultEvent};
use crate::crypto::{KdfCost, KdfParams, Keys, MasterKey, SealType, MK_LEN};
use crate::model::{AttachmentBundle, IndexEntry, Item, ItemDraft, ItemSummary, Tombstone};
use crate::recovery::{RecoveryCode, RecoveryEnvelope};
use crate::session::{SessionManager, TOKEN_LEN};
use crate::sync::{SyncEngine, SyncPlan, SyncSummary, VaultRead};
use crate::vault::UnlockedVault;
use crate::Result;

// ---------------------------------------------------------------------------
// A 层 · 数据平面
// ---------------------------------------------------------------------------

/// A 层 **crypto** 插件（`docs/plugin-architecture.md` §3.1；地基）。
///
/// 加密原语门面：KDF 派生、AEAD 密封/打开、自描述密文格式。无状态。
pub trait CryptoService: Send + Sync {
    /// 当前 UTC 时间（ISO-8601，`vault.status`/revision 用）。
    fn now_iso(&self) -> String;
    /// 生产 KDF 参数（Argon2id(m=64MiB, t=3, p=4)）。
    fn default_kdf(&self) -> KdfParams;
    /// 主密码 → 主密钥 → K_data / K_audit 分叉。
    fn derive_keys(&self, password: &str, params: &KdfParams) -> Result<Keys>;
    /// 密封（自描述密文容器；格式见 `docs/crypto.md`）。
    fn seal(&self, key: &[u8], kind: SealType, object_id: &str, plaintext: &[u8]) -> Vec<u8>;
    /// 打开（失败统一 [`Error::Decrypt`]，防 oracle）。
    fn open(
        &self,
        key: &[u8],
        expected_kind: SealType,
        object_id: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>>;
}

/// crypto 服务默认实现（薄包装 `crate::crypto` 自由函数）。
pub struct Crypto;

impl CryptoService for Crypto {
    fn now_iso(&self) -> String {
        crate::crypto::now_iso()
    }
    fn default_kdf(&self) -> KdfParams {
        crate::crypto::default_kdf_params()
    }
    fn derive_keys(&self, password: &str, params: &KdfParams) -> Result<Keys> {
        Ok(params.derive_master_key(password)?.derive_keys())
    }
    fn seal(&self, key: &[u8], kind: SealType, object_id: &str, plaintext: &[u8]) -> Vec<u8> {
        crate::crypto::seal(key, kind, object_id, plaintext)
    }
    fn open(
        &self,
        key: &[u8],
        expected_kind: SealType,
        object_id: &str,
        blob: &[u8],
    ) -> Result<Vec<u8>> {
        crate::crypto::open(key, expected_kind, object_id, blob)
    }
}

/// A 层 **vault-store** 插件（§3.1；依赖 crypto）。
///
/// 加密数据落盘服务：条目/索引/墓碑/附件 CRUD、CAS、30 天延迟硬删。
/// 状态由宿主持有（守护进程的解锁态），服务面 = 对外命令 + 索引读取；
/// 同步引擎的写侧通道（`import_*`/`hard_delete`）为 crate 内部面，不属
/// 对外服务契约（与 [`VaultRead`] 读侧抽象对称）。
pub trait VaultStoreService: Send + Sync {
    /// 会话密钥（K_data / K_audit）。
    fn keys(&self) -> &Keys;
    /// 数据目录。
    fn dir(&self) -> &Path;
    /// 解密态最小索引（含已删除条目）。
    fn list(&mut self) -> Result<Vec<ItemSummary>>;
    /// 单条完整解密条目。
    fn get(&self, id: Uuid) -> Result<Item>;
    /// 新建/整条替换（CAS；`expected_revision` 不匹配 → [`Error::Conflict`]）。
    fn put(
        &mut self,
        id: Option<Uuid>,
        draft: ItemDraft,
        expected_revision: Option<String>,
    ) -> Result<Item>;
    /// 软删除（墓碑；30 天延迟硬删）。
    fn delete(&mut self, id: Uuid) -> Result<Tombstone>;
    /// 过期墓碑硬删（同步确认口由 sync-engine 裁决）。
    fn purge_expired(&mut self, now: &str) -> Result<usize>;
    /// 附件导出（文件条目）。
    fn export(&self, id: Uuid) -> Result<AttachmentBundle>;
    /// 加密索引快照（同步 diff/合并的一致性基点）。
    fn index_snapshot(&self) -> Vec<IndexEntry>;
    /// 全部本地墓碑（同步硬删裁决）。
    fn tombstones(&self) -> Vec<(Uuid, Tombstone)>;
}

impl VaultStoreService for UnlockedVault {
    fn keys(&self) -> &Keys {
        self.keys()
    }
    fn dir(&self) -> &Path {
        self.dir()
    }
    fn list(&mut self) -> Result<Vec<ItemSummary>> {
        self.list()
    }
    fn get(&self, id: Uuid) -> Result<Item> {
        self.get(id)
    }
    fn put(
        &mut self,
        id: Option<Uuid>,
        draft: ItemDraft,
        expected_revision: Option<String>,
    ) -> Result<Item> {
        self.put(id, draft, expected_revision)
    }
    fn delete(&mut self, id: Uuid) -> Result<Tombstone> {
        self.delete(id)
    }
    fn purge_expired(&mut self, now: &str) -> Result<usize> {
        self.purge_expired(now)
    }
    fn export(&self, id: Uuid) -> Result<AttachmentBundle> {
        self.export(id)
    }
    fn index_snapshot(&self) -> Vec<IndexEntry> {
        self.index_snapshot()
    }
    fn tombstones(&self) -> Vec<(Uuid, Tombstone)> {
        self.tombstones()
    }
}

/// A 层 **recovery** 插件（§3.1；依赖 crypto + vault-store）。
///
/// 恢复码、恢复信封、重加密轮换编排（轮换在 vault-store 侧
/// `recover_vault_with_params`，信封构件在本服务）。无状态。
pub trait RecoveryService: Send + Sync {
    /// 生成 40 字符恢复码（一次性展示）。
    fn generate_code(&self) -> RecoveryCode;
    /// 解析/校验恢复码（格式错误 → [`Error::InvalidRecoveryCode`]）。
    fn parse_code(&self, input: &str) -> Result<RecoveryCode>;
    /// 构建恢复信封（恢复码 + Argon2id 独立派生 K_recovery，`docs/recovery.md`）。
    fn build_envelope(
        &self,
        code: &RecoveryCode,
        mk: &MasterKey,
        kdf: KdfParams,
        cost: KdfCost,
    ) -> Result<RecoveryEnvelope>;
    /// 用恢复码打开信封取回主密钥副本。
    fn open_envelope(&self, envelope: &RecoveryEnvelope, code: &RecoveryCode) -> Result<MasterKey>;
}

/// recovery 服务默认实现（薄包装 `crate::recovery`）。
pub struct Recovery;

impl RecoveryService for Recovery {
    fn generate_code(&self) -> RecoveryCode {
        RecoveryCode::generate()
    }
    fn parse_code(&self, input: &str) -> Result<RecoveryCode> {
        RecoveryCode::parse(input)
    }
    fn build_envelope(
        &self,
        code: &RecoveryCode,
        mk: &MasterKey,
        kdf: KdfParams,
        cost: KdfCost,
    ) -> Result<RecoveryEnvelope> {
        RecoveryEnvelope::build(code, mk, kdf, cost)
    }
    fn open_envelope(&self, envelope: &RecoveryEnvelope, code: &RecoveryCode) -> Result<MasterKey> {
        envelope.open(code)
    }
}

/// A 层 **audit** 插件（§3.1；依赖 crypto）。
///
/// 追加日志 + HMAC 防篡改 + 密钥轮换验证链。状态由宿主持有
/// （守护进程是唯一写入方）。
pub trait AuditService: Send + Sync {
    /// 追加事件（HMAC 签名；密钥值永不明文）。
    fn append(&self, keys: &Keys, input: &EventInput) -> Result<AuditEvent>;
    /// 读全部事件（时间序）。
    fn read(&self) -> Result<Vec<AuditEvent>>;
    /// 事件总数。
    fn count(&self) -> Result<usize>;
    /// 验证 HMAC 链（轮换点前事件需旧钥，经 `resolve` 提供）。
    fn verify(
        &self,
        initial: &Keys,
        resolve: &dyn Fn(&str) -> Option<Zeroizing<[u8; MK_LEN]>>,
    ) -> Result<usize>;
}

impl AuditService for AuditLog {
    fn append(&self, keys: &Keys, input: &EventInput) -> Result<AuditEvent> {
        self.append(keys, input)
    }
    fn read(&self) -> Result<Vec<AuditEvent>> {
        self.read()
    }
    fn count(&self) -> Result<usize> {
        self.count()
    }
    fn verify(
        &self,
        initial: &Keys,
        resolve: &dyn Fn(&str) -> Option<Zeroizing<[u8; MK_LEN]>>,
    ) -> Result<usize> {
        self.verify(initial, resolve)
    }
}

/// A 层 **session** 插件（§3.1；无依赖）。
///
/// 令牌签发/校验/轮换。状态由宿主持有；签发/失效经事件总线广播
/// `session.unlocked` / `session.locked`（宿主编装总线，见
/// [`CoreServices::new_session`]）。
pub trait SessionService: Send + Sync {
    /// 签发新令牌（每次解锁轮换；`via` = 解锁方式）。
    fn issue_with(&mut self, via: SessionVia) -> [u8; TOKEN_LEN];
    /// 校验令牌（错误/过期/未解锁 → false，防探测）。
    fn validate(&self, token: &[u8]) -> bool;
    /// 是否已解锁。
    fn is_unlocked(&self) -> bool;
    /// 会话时长（空闲超时判定）。
    fn elapsed(&self) -> Option<Duration>;
    /// 失效令牌（`reason` = 锁定原因）。
    fn invalidate_with(&mut self, reason: LockReason);
}

impl SessionService for SessionManager {
    fn issue_with(&mut self, via: SessionVia) -> [u8; TOKEN_LEN] {
        self.issue_with(via)
    }
    fn validate(&self, token: &[u8]) -> bool {
        self.validate(token)
    }
    fn is_unlocked(&self) -> bool {
        self.is_unlocked()
    }
    fn elapsed(&self) -> Option<Duration> {
        self.elapsed()
    }
    fn invalidate_with(&mut self, reason: LockReason) {
        self.invalidate_with(reason)
    }
}

// ---------------------------------------------------------------------------
// B 层 · 能力域
// ---------------------------------------------------------------------------

/// B 层 **sync-engine** 插件（§3.2；注入 vault-store + storage-backend）。
///
/// 变更发现、CAS 冲突收敛、墓碑同步（`docs/sync.md`）。读侧经
/// [`VaultRead`] 视图（守护进程短锁实现，网络 I/O 不持锁）；写侧消费
/// vault-store 的 crate 内部通道（`UnlockedVault` 的 `import_*`/`hard_delete`）。
/// 依赖注入 = 构造时持 `&dyn StorageBackend`（可插拔后端）。
pub trait SyncEngineService: Send + Sync {
    /// 阶段 1：抓取（远端对比 + 变更发现；只读本地）。
    fn fetch_round(&self, view: &dyn VaultRead, now: &str) -> Result<SyncPlan>;
    /// 阶段 2：应用（本地落盘；调用方须持 vault 短写锁）。
    fn apply_round(&self, vault: &mut UnlockedVault, plan: &mut SyncPlan) -> Result<()>;
    /// 完整一轮（fetch + apply）。
    fn run_round(&self, vault: &mut UnlockedVault, now: &str) -> Result<SyncSummary>;
}

impl SyncEngineService for SyncEngine<'_> {
    fn fetch_round(&self, view: &dyn VaultRead, now: &str) -> Result<SyncPlan> {
        self.fetch_round(view, now)
    }
    fn apply_round(&self, vault: &mut UnlockedVault, plan: &mut SyncPlan) -> Result<()> {
        self.apply_round(vault, plan)
    }
    fn run_round(&self, vault: &mut UnlockedVault, now: &str) -> Result<SyncSummary> {
        self.run_round(vault, now)
    }
}

// ---------------------------------------------------------------------------
// C 层 · 装配（宿主侧）
// ---------------------------------------------------------------------------

/// C 层装配点（模拟 Cordis ctx：服务容器 + 事件总线；§3.3）。
///
/// 无状态地基服务（crypto / recovery）随装配点分发；有状态数据平面服务
/// （session / vault-store / audit）由宿主持有状态，经本装配点挂总线：
///
/// - [`CoreServices::new_session`]：session 服务（签发/失效 → 总线广播）；
/// - [`CoreServices::attach_vault`]：vault-store 服务（写成功 → `item.changed`）；
/// - [`CoreServices::subscribe`] / [`CoreServices::emit`]：总线访问
///   （未来 M2 的 IPC 通知桥在此订阅，Rust 事件 → IPC 通知 → TS 重新 emit）。
pub struct CoreServices {
    bus: Arc<EventBus>,
    crypto: Box<dyn CryptoService>,
    recovery: Box<dyn RecoveryService>,
}

impl Default for CoreServices {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreServices {
    /// 默认装配：真实 crypto / recovery 实现 + 新事件总线。
    pub fn new() -> CoreServices {
        CoreServices {
            bus: Arc::new(EventBus::new()),
            crypto: Box::new(Crypto),
            recovery: Box::new(Recovery),
        }
    }

    /// 事件总线引用（订阅 / 广播 / 测试断言）。
    pub fn bus(&self) -> &Arc<EventBus> {
        &self.bus
    }

    /// 订阅总线事件（观察广播；订阅者须非阻塞）。
    pub fn subscribe(&self, sink: Arc<dyn EventSink>) {
        self.bus.subscribe(sink);
    }

    /// 广播事件（宿主侧主动触发；与插件内广播同一总线）。
    pub fn emit(&self, event: &VaultEvent) {
        self.bus.emit(event);
    }

    /// A 层 crypto 服务（无状态地基）。
    pub fn crypto(&self) -> &dyn CryptoService {
        self.crypto.as_ref()
    }

    /// A 层 recovery 服务（无状态地基）。
    pub fn recovery(&self) -> &dyn RecoveryService {
        self.recovery.as_ref()
    }

    /// 构造 A 层 session 服务（已挂总线：解锁 → `session.unlocked`、
    /// 锁定 → `session.locked`；宿主每次启动装配一个）。
    pub fn new_session(&self) -> SessionManager {
        let mut session = SessionManager::new();
        session.attach_bus(Arc::clone(&self.bus));
        session
    }

    /// 装配 A 层 vault-store 服务：解锁后挂总线（写成功 → `item.changed`）。
    pub fn attach_vault(&self, vault: &mut UnlockedVault) {
        vault.attach_bus(Arc::clone(&self.bus));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditLog, AuditResult};
    use crate::bus::FnSink;
    use crate::crypto::test_kdf_params;
    use crate::model::ItemDraft;
    use crate::vault::init_vault_with_params;
    use crate::Error;
    use std::sync::Mutex;

    /// 收集事件的测试订阅者。
    struct Recorder(Arc<Mutex<Vec<VaultEvent>>>);

    fn recorder() -> (Arc<Recorder>, Arc<Mutex<Vec<VaultEvent>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let r = Arc::new(Recorder(Arc::clone(&events)));
        (r, events)
    }

    impl EventSink for Recorder {
        fn on_event(&self, event: &VaultEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    fn test_vault(dir: &Path) -> UnlockedVault {
        let mut audit = AuditLog::open(dir).unwrap();
        init_vault_with_params(dir, "pw", false, &mut audit, &test_kdf_params()).unwrap();
        UnlockedVault::unlock(dir, "pw").unwrap()
    }

    /// 事件总线契约：`item.changed` 一事件三方响应（sync-engine 推送 /
    /// audit 记录 / ui 刷新；互不依赖、无需返回值聚合 → `emit`）。
    #[test]
    fn item_changed_three_party_response() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = test_vault(dir.path());

        let bus = Arc::new(EventBus::new());
        let (sync_sink, sync_seen) = recorder();
        let (audit_sink, audit_seen) = recorder();
        let (ui_sink, ui_seen) = recorder();
        bus.subscribe(sync_sink);
        bus.subscribe(audit_sink);
        bus.subscribe(ui_sink);
        vault.attach_bus(bus);

        // 新建 → 三方都收到 item.changed（deleted=false，revision 递增）
        let item = vault
            .put(
                None,
                ItemDraft::Login {
                    name: "GitHub".into(),
                    username: "octocat".into(),
                    password: "s3cr3t".into(),
                    uris: vec![],
                    custom: vec![],
                },
                None,
            )
            .unwrap();
        for (name, seen) in [
            ("sync", &sync_seen),
            ("audit", &audit_seen),
            ("ui", &ui_seen),
        ] {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1, "{name} 应收到 1 个事件");
            match &seen[0] {
                VaultEvent::ItemChanged {
                    item_id,
                    revision_date,
                    kind,
                    deleted,
                } => {
                    assert_eq!(*item_id, item.id());
                    assert_eq!(*revision_date, item.revision().to_string());
                    assert_eq!(kind, "login");
                    assert!(!deleted);
                }
                other => panic!("{name} 收到非 item.changed 事件：{other:?}"),
            }
        }

        // 软删除 → 三方收到 deleted=true 且 revision 前进
        let before = item.revision().to_string();
        vault.delete(item.id()).unwrap();
        for seen in [&sync_seen, &audit_seen, &ui_seen] {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 2);
            match &seen[1] {
                VaultEvent::ItemChanged {
                    item_id,
                    revision_date,
                    deleted,
                    ..
                } => {
                    assert_eq!(*item_id, item.id());
                    assert!(deleted);
                    assert!(*revision_date > before, "删除后 revision 前进");
                }
                other => panic!("非 item.changed 事件：{other:?}"),
            }
        }
    }

    /// 三方互不依赖：一个订阅者失败不影响其余（emit 语义）。
    #[test]
    fn item_changed_subscriber_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = test_vault(dir.path());
        let bus = Arc::new(EventBus::new());
        bus.subscribe(Arc::new(FnSink::new(|_| panic!("订阅者故障"))));
        let (ui_sink, ui_seen) = recorder();
        bus.subscribe(ui_sink);
        vault.attach_bus(bus);
        vault
            .put(
                None,
                ItemDraft::Note {
                    name: "n".into(),
                    content: "c".into(),
                },
                None,
            )
            .unwrap();
        assert_eq!(ui_seen.lock().unwrap().len(), 1);
    }

    /// 会话事件：解锁 → `session.unlocked`（via），锁定 → `session.locked`（reason）。
    #[test]
    fn session_unlocked_locked_events() {
        let core = CoreServices::new();
        let (sink, seen) = recorder();
        core.subscribe(sink);
        let mut session = core.new_session();

        session.issue_with(SessionVia::Password);
        session.invalidate_with(LockReason::Timeout);
        session.issue_with(SessionVia::Recovery);
        session.invalidate_with(LockReason::Manual);

        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 4);
        assert!(matches!(
            &seen[0],
            VaultEvent::SessionUnlocked {
                via: SessionVia::Password
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

    /// 装配点：crypto / recovery 服务可用（密封往返 + 信封往返）。
    #[test]
    fn core_services_crypto_recovery_roundtrip() {
        let core = CoreServices::new();

        // crypto 服务
        let params = test_kdf_params();
        let keys = core.crypto().derive_keys("pw", &params).expect("KDF 派生");
        let blob = core
            .crypto()
            .seal(keys.k_data.as_ref(), SealType::Item, "obj", b"hello");
        let opened = core
            .crypto()
            .open(keys.k_data.as_ref(), SealType::Item, "obj", &blob);
        assert_eq!(opened.unwrap(), b"hello");
        // 错误密钥 → 统一 Decrypt
        let other = core.crypto().derive_keys("pw2", &params).unwrap();
        assert!(matches!(
            core.crypto()
                .open(other.k_data.as_ref(), SealType::Item, "obj", &blob),
            Err(Error::Decrypt)
        ));

        // recovery 服务：恢复码往返 + 信封打开
        let recovery = core.recovery();
        let code = recovery.generate_code();
        let parsed = recovery.parse_code(&code.display()).unwrap();
        assert_eq!(parsed.display(), code.display());
        let mk = params.derive_master_key("pw").unwrap();
        let envelope = recovery
            .build_envelope(&code, &mk, params.clone(), KdfCost::from(&params))
            .unwrap();
        let opened_mk = recovery.open_envelope(&envelope, &parsed).unwrap();
        assert_eq!(opened_mk.as_bytes(), mk.as_bytes());
        // 错误恢复码 → 打不开（K_recovery 不符）
        let wrong = recovery.generate_code();
        assert!(recovery.open_envelope(&envelope, &wrong).is_err());
    }

    /// vault-store 服务 trait 对象可用（经 dyn 走通 CRUD 面）。
    #[test]
    fn vault_store_service_trait_object() {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = test_vault(dir.path());
        {
            let service: &mut dyn VaultStoreService = &mut vault;
            assert!(service.dir().is_dir());
            let item = service
                .put(
                    None,
                    ItemDraft::Secret {
                        name: "k".into(),
                        value: "v".into(),
                        purpose: String::new(),
                        expires_at: None,
                    },
                    None,
                )
                .unwrap();
            assert_eq!(service.list().unwrap().len(), 1);
            assert_eq!(service.get(item.id()).unwrap().id(), item.id());
            service.delete(item.id()).unwrap();
            assert_eq!(service.tombstones().len(), 1);
        }
        // 审计面（追加 + 验证链）
        let audit = AuditLog::open(dir.path()).unwrap();
        let service: &dyn AuditService = &audit;
        let keys = vault.keys().clone();
        service
            .append(&keys, &EventInput::new("lk", "test", AuditResult::Allowed))
            .unwrap();
        assert_eq!(service.count().unwrap(), 2);
        assert!(service.verify(&keys, &|_| None).is_ok());
    }
}
