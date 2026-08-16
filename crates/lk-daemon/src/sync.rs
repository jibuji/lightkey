//! C 层 daemon 宿主 · 同步轮次执行边界（M1；`docs/plugin-architecture.md` §3.3）。
//!
//! 两阶段（G1 根治，网络 I/O 全程不持任何守护进程锁）：
//!
//! 1. 抓取：密钥/索引等经 [`LockedVaultView`] 短读锁读取 + 全部网络 I/O；
//! 2. 应用：vault 短写锁内按当前状态复核后落盘（CAS 兜底）。
//!
//! 锁/恢复竞态（密钥已变）→ 本轮放弃（Err），下一轮重试。
//! 水位/摘要/风暴等级在锁外持久化（`sync-state.json`）。
//!
//! M2：规则与条目同路径同步（视图新增 `rule*` 读取面）。

use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use lk_core::crypto::Keys;
use lk_core::ipc::*;
use lk_core::model::{IndexEntry, Item, Rule, Tombstone};
use lk_core::storage::{backend_from_url, StorageBackend};
use lk_core::sync::{storm_level_after, SyncEngine};
use lk_core::vault::UnlockedVault;
use lk_core::Error;
use serde_json::{json, Value};

use super::config::read_config;
use super::{extract_token, session_invalid, SharedDaemon};

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

/// [`VaultRead`] 的守护进程侧实现：每次方法调用独立获取**短读锁**（仅本地
/// 内存/磁盘访问），网络 I/O 期间不持任何锁。`keys` 为轮次开始时的快照
/// （应用阶段复核其仍与解锁态一致；锁定/恢复竞态 → 本轮放弃）。
struct LockedVaultView {
    vault: Arc<RwLock<Option<UnlockedVault>>>,
    keys: Keys,
}

impl lk_core::sync::VaultRead for LockedVaultView {
    fn keys(&self) -> Keys {
        self.keys.clone()
    }

    fn index_snapshot(&self) -> lk_core::Result<Vec<IndexEntry>> {
        let v = self.vault.read().unwrap();
        v.as_ref()
            .map(|v| v.index_snapshot())
            .ok_or(Error::SessionInvalid)
    }

    fn item(&self, id: uuid::Uuid) -> lk_core::Result<Item> {
        let v = self.vault.read().unwrap();
        v.as_ref().ok_or(Error::SessionInvalid)?.get(id)
    }

    fn item_with_blob(&self, id: uuid::Uuid) -> lk_core::Result<(Item, Vec<u8>)> {
        let v = self.vault.read().unwrap();
        let v = v.as_ref().ok_or(Error::SessionInvalid)?;
        let item = v.get(id)?;
        let blob = v.item_blob(id)?;
        Ok((item, blob))
    }

    fn rule(&self, id: uuid::Uuid) -> lk_core::Result<Rule> {
        let v = self.vault.read().unwrap();
        v.as_ref().ok_or(Error::SessionInvalid)?.get_rule(id)
    }

    fn rule_with_blob(&self, id: uuid::Uuid) -> lk_core::Result<(Rule, Vec<u8>)> {
        let v = self.vault.read().unwrap();
        let v = v.as_ref().ok_or(Error::SessionInvalid)?;
        let rule = v.get_rule(id)?;
        let blob = v.rule_blob(id)?;
        Ok((rule, blob))
    }

    fn rule_revision(&self, id: uuid::Uuid) -> Option<String> {
        self.vault
            .read()
            .unwrap()
            .as_ref()
            .and_then(|v| v.rule_revision(id))
    }

    fn tomb_blob(&self, id: uuid::Uuid) -> lk_core::Result<Vec<u8>> {
        let v = self.vault.read().unwrap();
        v.as_ref().ok_or(Error::SessionInvalid)?.tomb_blob(id)
    }

    fn attachment_blobs(
        &self,
        attach_id: uuid::Uuid,
    ) -> lk_core::Result<lk_core::sync::AttachmentBlobs> {
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

    fn tombstones(&self) -> lk_core::Result<Vec<(uuid::Uuid, Tombstone)>> {
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
    // 配置热更新（CLI 直接写盘；每轮重读）
    let fresh = read_config(&shared.dir);
    *shared.config.write().unwrap() = fresh.clone();
    let cfg = fresh.sync.clone().ok_or(SyncFail::NotConfigured)?;
    if cfg.validate().is_err() {
        return Err(SyncFail::NotConfigured);
    }
    let creds = super::config::load_sync_credentials(&cfg.url).map_err(SyncFail::Credentials)?;
    let backend: Box<dyn StorageBackend> =
        backend_from_url(&cfg.url, creds).map_err(SyncFail::Engine)?;
    run_sync_round_with(shared, backend)
}

/// 执行一轮同步（后端注入；并发回归测试用）。
pub fn run_sync_round_with(
    shared: &SharedDaemon,
    backend: Box<dyn StorageBackend>,
) -> std::result::Result<lk_core::sync::SyncSummary, SyncFail> {
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
    state: &Mutex<super::Daemon>,
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
pub fn sync_fail_response(id: Value, e: &SyncFail) -> RpcResponse {
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
