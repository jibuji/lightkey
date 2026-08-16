//! 同步与变更发现（规格：`docs/sync.md`、`docs/data-model.md` §4/§6）。
//!
//! 设计要点（均为决议拍板，勿自行变更）：
//!
//! - BYO 存储（WebDAV / S3 / 本地模拟 `file://`），无推送、无中间态加载、
//!   静默轮询（默认 60s，可配 15s~24h）。
//! - 每轮协议：GET 远端 `index.lk`（加密）→ 解密对比本地索引 → 有差异才
//!   拉取条目（含墓碑）→ 本地较新则 CAS 上传 → 墓碑收敛 → 合并重写远端索引。
//! - CAS：上传携带 base ETag（存储端 `If-Match`/`If-None-Match`）；校验失败
//!   → CAS 冲突 → 整条目 last-write-wins（revisionDate 更晚者胜；同 revision
//!   按内容 SHA-256 确定性决胜，保证收敛）。
//! - 墓碑：删除在多端传播；硬删需「本端墓碑 ≥ 30 天 且 已同步确认」（远端
//!   索引已反映该墓碑）——远端文件与本地同时清除。
//! - 失败语义：任何一步失败（网络/存储 4xx/5xx/解密异常）→ 本轮放弃，保留
//!   本地状态，下一轮重试；远端密文被篡改 → [`Error::SyncAnomaly`]（报
//!   「同步数据异常」，不自动覆盖本地）。
//! - 首次同步 / 远端索引丢失 → 全量拉取（list 远端对象重建合成索引再走常规
//!   收敛），不阻塞解锁。
//! - 冲突风暴保护：单轮差异过大（> [`STORM_THRESHOLD`]）→ 轮询退避
//!   （指数 ×2，至 [`MAX_SYNC_INTERVAL_SECS`] 上限）。
//! - 已知边界（诚实记录）：对端离线超过 30 天硬删窗口后重新上线，可能把
//!   过期条目当新条目推回（远端无墓碑可对抗）；规格以 last-write-wins 兜底
//!   （data-model.md §4.2「硬删前若对端仍持旧条目」），本实现遵循该语义。
//! - 存储端零知识：只存密文 blob（文件名 = 对象 id，不含内容信息；同步排序
//!   依据加密索引内的 revisionDate，文件名无需时间戳）。
//! - **两阶段并发结构（G1 根治，船长 2026-08-15 定案）**：一轮同步拆为
//!   抓取（只读本地 + 全部网络 I/O，不持守护进程锁）与应用（纯本地写入，
//!   守护进程持短写锁）两阶段；网络 I/O 期间前台命令照常服务。一致性模型：
//!   以抓取时刻的本地索引快照为基点——只上传与快照 revision 一致的密文
//!   （并发更新 → 本轮跳过，下轮再推），合并索引以快照 + 本轮已缓冲的远端
//!   条目为底 → 远端索引引用的密文恒与索引条目一致；应用阶段逐条复核
//!   （本地已更新且不更旧 → 跳过），数据层冲突收敛仍由 CAS + last-write-wins
//!   兜底（不削弱）。

use std::cmp::Ordering;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sha2::Digest;

use crate::crypto::{open, parse_iso, seal, Keys, SealType};
use crate::model::{
    AttachmentMeta, IndexEntry, Item, ObjectKind, Rule, Tombstone, TOMBSTONE_GRACE,
};
use crate::storage::{valid_key, PutOutcome, StorageBackend, INDEX_KEY};
use crate::vault::UnlockedVault;
use crate::{Error, Result};

// ---------------------------------------------------------------------------
// 常量 / 配置
// ---------------------------------------------------------------------------

/// 轮询间隔默认：60s。
pub const DEFAULT_SYNC_INTERVAL_SECS: u64 = 60;
/// 轮询间隔可配下限：15s。
pub const MIN_SYNC_INTERVAL_SECS: u64 = 15;
/// 轮询间隔可配上限：24h。
pub const MAX_SYNC_INTERVAL_SECS: u64 = 24 * 3600;
/// 冲突风暴阈值：单轮差异（拉+推）超过该值 → 退避轮询频率。
pub const STORM_THRESHOLD: usize = 64;
/// 索引 CAS 冲突重试上限（重拉重合并；耗尽则本轮部分完成，下轮继续）。
pub const MAX_INDEX_CAS_RETRIES: usize = 3;
/// 单条目 CAS 冲突后的 LWW 重试上限。
pub const MAX_PUSH_RETRIES: usize = 3;

/// 同步配置（`lk config sync set` 写入 `config.json` 的 `sync` 段）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncConfig {
    /// BYO 存储 URL：`file://`（本地模拟）/ `http(s)://`（WebDAV）/ `s3://`。
    pub url: String,
    /// 轮询间隔秒数（15~86400，默认 60）。
    pub interval_secs: u64,
}

impl SyncConfig {
    /// 校验配置（URL 协议 + 间隔范围）；非法 → [`Error::SyncConfig`]。
    pub fn validate(&self) -> Result<()> {
        if !(MIN_SYNC_INTERVAL_SECS..=MAX_SYNC_INTERVAL_SECS).contains(&self.interval_secs) {
            return Err(Error::SyncConfig(format!(
                "轮询间隔须在 {}s~{}s 之间（当前 {}s）",
                MIN_SYNC_INTERVAL_SECS, MAX_SYNC_INTERVAL_SECS, self.interval_secs
            )));
        }
        let scheme = self
            .url
            .split_once("://")
            .map(|(s, _)| s)
            .unwrap_or_default();
        if !matches!(scheme, "file" | "http" | "https" | "s3") {
            return Err(Error::SyncConfig(format!(
                "不支持的存储协议 {scheme:?}（支持 file:// / http(s):// / s3://）"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 摘要 / 状态
// ---------------------------------------------------------------------------

/// 一轮同步的变更摘要（`sync.trigger` / `sync.poll` 返回；**不返回内容**）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncSummary {
    /// 本轮是否实际执行（`sync.poll` 尚未有轮次时 false）。
    pub ran: bool,
    /// 拉取条目数（含墓碑与附件）。
    pub pulled: usize,
    /// 推送条目数（含墓碑与附件）。
    pub pushed: usize,
    /// CAS 冲突收敛次数（last-write-wins 裁决）。
    pub conflicts: usize,
    /// 硬删条目数（30 天 + 已同步确认）。
    pub purged: usize,
    /// 是否有任何变更。
    pub changed: bool,
    /// 非致命提示（如远端对象缺失、附件分块暂缺）。
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl SyncSummary {
    pub fn is_clean(&self) -> bool {
        self.pulled == 0 && self.pushed == 0 && self.purged == 0
    }
}

/// 同步运行状态（守护进程持久化到 `sync-state.json`）。
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SyncState {
    /// 最近成功轮询时间（ISO-8601 UTC；`vault.status` 的同步水位）。
    pub watermark: Option<String>,
    /// 最近一轮摘要。
    pub last_summary: Option<SyncSummary>,
    /// 连续风暴轮数（单轮差异过大 +1，正常轮归零）。
    pub storm_level: u32,
}

/// 风暴退避后的下次轮询间隔：`base * 2^level`，封顶 [`MAX_SYNC_INTERVAL_SECS`]。
pub fn next_poll_interval(base_secs: u64, storm_level: u32) -> u64 {
    let base = base_secs.clamp(MIN_SYNC_INTERVAL_SECS, MAX_SYNC_INTERVAL_SECS);
    base.saturating_mul(2u64.saturating_pow(storm_level.min(14)))
        .min(MAX_SYNC_INTERVAL_SECS)
}

/// 风暴等级更新：单轮差异（拉+推）超过阈值 → 等级 +1；否则归零。
pub fn storm_level_after(diff: usize, current: u32) -> u32 {
    if diff > STORM_THRESHOLD {
        current.saturating_add(1)
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// 引擎（两阶段：抓取无锁 → 应用短锁；G1 根治）
// ---------------------------------------------------------------------------

/// last-write-wins 裁决结果。
enum Lww {
    Local,
    Remote,
    Tie,
}

/// 整条目 last-write-wins：revisionDate 更晚者胜；同 revision 按内容
/// SHA-256 确定性决胜（两端同规则 → 收敛）；内容相同 → Tie。
fn lww(local: &Item, remote: &Item) -> Lww {
    match local.revision().cmp(remote.revision()) {
        Ordering::Greater => Lww::Local,
        Ordering::Less => Lww::Remote,
        Ordering::Equal => {
            let lh = item_content_hash(local);
            let rh = item_content_hash(remote);
            match lh.cmp(&rh) {
                Ordering::Greater => Lww::Local,
                Ordering::Less => Lww::Remote,
                Ordering::Equal => Lww::Tie,
            }
        }
    }
}

fn item_content_hash(item: &Item) -> [u8; 32] {
    // 条目明文序列化失败视为内容不同（防御性；正常路径不会发生）
    item.to_plaintext()
        .map(|pt| sha2::Sha256::digest(&pt).into())
        .unwrap_or([0u8; 32])
}

/// 附件抓取/推送的成组数据（元数据密文 + 已解密元数据 + 分块密文）。
pub type AttachmentBlobs = (AttachmentMeta, Vec<u8>, Vec<(u32, Vec<u8>)>);

/// 同步引擎的本地 vault 只读视图（阶段 1 用）。
///
/// 守护进程侧实现：每次方法调用独立获取**短读锁**（仅本地内存/磁盘访问，
/// 不跨网络），网络 I/O 期间不持任何锁；测试直接以 [`UnlockedVault`] 实现。
pub trait VaultRead {
    /// 密钥快照（抓取阶段解密/加密；应用阶段复核其仍与解锁态一致）。
    fn keys(&self) -> Keys;

    /// 索引快照（diff/合并的一致性基点；每次 CAS 重试取新快照）。
    fn index_snapshot(&self) -> Result<Vec<IndexEntry>>;

    /// 解密态条目（拉取 LWW 初筛）。
    fn item(&self, id: Uuid) -> Result<Item>;

    /// 条目 + 密文（**同一一致性点**读取；推送/冲突裁决用）。
    fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)>;

    /// 解密态规则（M2；拉取 LWW 初筛）。
    fn rule(&self, id: Uuid) -> Result<Rule>;

    /// 规则 + 密文（**同一一致性点**读取；推送用）。
    fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)>;

    /// 规则当前修订号（索引内——规则体无 revision 字段；LWW 初筛用）。
    fn rule_revision(&self, id: Uuid) -> Option<String>;

    /// 墓碑密文（可能不存在——远端墓碑缺失时由引擎合成）。
    fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>>;

    /// 附件元数据密文 + 全部分块密文（推送用；单次一致读取）。
    fn attachment_blobs(&self, attach_id: Uuid) -> Result<AttachmentBlobs>;

    /// 附件远端文件键列表（远端硬删用）。
    fn attachment_keys(&self, attach_id: Uuid) -> Vec<String>;

    /// 全部本地墓碑（硬删裁决）。
    fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>>;
}

impl VaultRead for UnlockedVault {
    fn keys(&self) -> Keys {
        self.keys().clone()
    }

    fn index_snapshot(&self) -> Result<Vec<IndexEntry>> {
        Ok(self.index_snapshot())
    }

    fn item(&self, id: Uuid) -> Result<Item> {
        self.get(id)
    }

    fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)> {
        let item = self.get(id)?;
        let blob = self.item_blob(id)?;
        Ok((item, blob))
    }

    fn rule(&self, id: Uuid) -> Result<Rule> {
        self.get_rule(id)
    }

    fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)> {
        let rule = self.get_rule(id)?;
        let blob = self.rule_blob(id)?;
        Ok((rule, blob))
    }

    fn rule_revision(&self, id: Uuid) -> Option<String> {
        self.rule_revision(id)
    }

    fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>> {
        self.tomb_blob(id)
    }

    fn attachment_blobs(&self, attach_id: Uuid) -> Result<AttachmentBlobs> {
        let meta = self.attachment_meta(attach_id)?;
        let meta_blob = self.attach_meta_blob(attach_id)?;
        let mut chunks = Vec::with_capacity(meta.chunks as usize);
        for i in 0..meta.chunks {
            chunks.push((i, self.chunk_blob(attach_id, i)?));
        }
        Ok((meta, meta_blob, chunks))
    }

    fn attachment_keys(&self, attach_id: Uuid) -> Vec<String> {
        self.attachment_keys(attach_id)
    }

    fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>> {
        Ok(self.tombstones())
    }
}

/// 一轮同步的本地侧应用计划（`fetch_round` 产物；`apply_round` 消费）。
pub struct SyncPlan {
    /// 摘要（pulled/purged 由应用阶段按实际应用计数回填）。
    pub summary: SyncSummary,
    /// 待导入的远端条目（密文原样缓冲；抓取阶段已解密校验，应用阶段复核）。
    imports: Vec<PendingImport>,
    /// 待本地硬删的条目（id + 裁决时的墓碑 revision；应用阶段复核）。
    hard_delete: Vec<(Uuid, String)>,
}

impl SyncPlan {
    /// 按 id upsert 待导入条目：同一条目在 CAS 重试间被再次缓冲（远端
    /// revision 前进）时，以最新缓冲替换旧缓冲——保证合并索引（`pending`）
    /// 与抓取阶段看到的远端 revision 恒一致，旧快照不得覆盖更新版本。
    fn upsert_import(&mut self, imp: PendingImport) {
        self.imports.retain(|i| i.id != imp.id);
        self.imports.push(imp);
    }
}

/// 待导入的远端对象（条目或规则；M2 起规则与条目同路径同步）。
enum PendingObject {
    Item(Item),
    Rule(Rule),
}

/// 待导入的远端对象。
struct PendingImport {
    id: Uuid,
    /// 对象类型（密文文件名与索引 kind 同源）。
    kind: ObjectKind,
    /// 远端索引修订号（规则体无 revision，以索引为准；条目与体内一致）。
    revision: String,
    /// 远端索引 deleted 标记（规则删除状态在索引内）。
    deleted: bool,
    /// 对象密文（原样落盘）。
    blob: Vec<u8>,
    /// 已解密对象（校验 + 应用阶段 LWW 复核）。
    object: PendingObject,
    /// (密文, 已解密)；远端墓碑缺失 → 引擎合成。
    tomb: Option<(Vec<u8>, Tombstone)>,
    attachments: Vec<PendingAttachment>,
}

/// 待导入的附件（元数据密文 + 已解密元数据 + 分块密文）。
struct PendingAttachment {
    meta_blob: Vec<u8>,
    meta: AttachmentMeta,
    chunks: Vec<(u32, Vec<u8>)>,
}

/// 推送结果。
enum PushResult {
    /// 已推送（远端已反映该条目的快照状态）。
    Pushed,
    /// 快照一致性守卫：条目在 diff 后被并发更新（或本地缺失）→ 本轮跳过
    /// （合并索引恢复远端原状/剔除；下轮再推）。
    Skipped,
    /// CAS 冲突后采纳远端（已缓冲到计划；合并索引以其远端版本为准）。
    Adopted,
}

/// 两阶段同步引擎。
///
/// 一轮同步（守护进程侧两阶段调用，网络 I/O 不持任何守护进程锁）：
///
/// 1. [`SyncEngine::fetch_round`]：只读本地（经 [`VaultRead`] 短锁）+ 全部
///    网络 I/O；产物为 [`SyncPlan`]（拉取缓冲 + 硬删计划 + 网络侧摘要）。
/// 2. [`SyncEngine::apply_round`]：纯本地写入（调用方持短写锁；无网络），
///    逐条复核「同步期间命令是否改了同一条目」——CAS 兜底：本地已更新且
///    不更旧 → 跳过，下轮收敛（见模块文档「两阶段并发结构」）。
pub struct SyncEngine<'a> {
    remote: &'a dyn StorageBackend,
}

impl<'a> SyncEngine<'a> {
    pub fn new(remote: &'a dyn StorageBackend) -> SyncEngine<'a> {
        SyncEngine { remote }
    }

    // -- 解密辅助（失败统一 SyncAnomaly：篡改不自动覆盖）--------------------

    fn open_index(&self, view: &dyn VaultRead, blob: &[u8]) -> Result<Vec<IndexEntry>> {
        open(
            view.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            blob,
        )
        .map_err(|_| Error::SyncAnomaly("远端 index.lk 无法解密（可能被篡改）".into()))
        .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
    }

    fn open_item(&self, view: &dyn VaultRead, key: &str, blob: &[u8]) -> Result<Item> {
        open(view.keys().k_data.as_ref(), SealType::Item, key, blob)
            .map_err(|_| Error::SyncAnomaly(format!("远端 {key} 无法解密（可能被篡改）")))
            .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
    }

    fn open_tomb(&self, view: &dyn VaultRead, key: &str, blob: &[u8]) -> Result<Tombstone> {
        open(view.keys().k_data.as_ref(), SealType::Tombstone, key, blob)
            .map_err(|_| Error::SyncAnomaly(format!("远端 {key} 无法解密（可能被篡改）")))
            .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
    }

    fn open_rule(&self, view: &dyn VaultRead, key: &str, blob: &[u8]) -> Result<Rule> {
        open(view.keys().k_data.as_ref(), SealType::Rule, key, blob)
            .map_err(|_| Error::SyncAnomaly(format!("远端 {key} 无法解密（可能被篡改）")))
            .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
    }

    /// 远端索引中某对象的条目（CAS 冲突 LWW 裁决用：规则修订号只在索引内）。
    fn remote_rule_entry(&self, view: &dyn VaultRead, id: Uuid) -> Result<Option<IndexEntry>> {
        match self.remote.get(INDEX_KEY)? {
            Some(g) => {
                let entries = self.open_index(view, &g.data)?;
                Ok(entries.into_iter().find(|e| e.id == id))
            }
            None => Ok(None),
        }
    }

    fn open_meta(&self, view: &dyn VaultRead, key: &str, blob: &[u8]) -> Result<AttachmentMeta> {
        open(view.keys().k_data.as_ref(), SealType::Attach, key, blob)
            .map_err(|_| Error::SyncAnomaly(format!("远端 {key} 无法解密（可能被篡改）")))
            .and_then(|pt| Ok(serde_json::from_slice(&pt)?))
    }

    // -- 远端索引 ----------------------------------------------------------

    /// 拉取远端索引。缺失（首次同步 / 索引丢失）→ 全量拉取：list 远端对象，
    /// 以条目密文重建合成索引（按索引重建，data-model.md §6）。
    fn fetch_remote_index(
        &self,
        view: &dyn VaultRead,
    ) -> Result<(HashMap<Uuid, IndexEntry>, Option<String>)> {
        match self.remote.get(INDEX_KEY)? {
            Some(g) => {
                let entries = self.open_index(view, &g.data)?;
                let map: HashMap<Uuid, IndexEntry> =
                    entries.into_iter().map(|e| (e.id, e)).collect();
                Ok((map, Some(g.etag)))
            }
            None => {
                let mut map = HashMap::new();
                for obj in self.remote.list()? {
                    if !valid_key(&obj.key) {
                        continue; // 只信已知形态的对象文件（防恶意键）
                    }
                    let Some(g) = self.remote.get(&obj.key)? else {
                        continue;
                    };
                    if obj.key.ends_with(".item.lk") {
                        let item = self.open_item(view, &obj.key, &g.data)?;
                        map.insert(
                            item.id(),
                            IndexEntry {
                                id: item.id(),
                                revision: item.revision().to_string(),
                                kind: ObjectKind::Item,
                                deleted: item.deleted(),
                            },
                        );
                    } else if obj.key.ends_with(".rule.lk") {
                        // 规则体无 revision：以创建时间作合成修订号（索引丢失
                        // 重建路径；稳定、零 churn——同一规则两端同值）
                        let rule = self.open_rule(view, &obj.key, &g.data)?;
                        map.insert(
                            rule.id,
                            IndexEntry {
                                id: rule.id,
                                revision: rule.created.clone(),
                                kind: ObjectKind::Rule,
                                deleted: false,
                            },
                        );
                    }
                }
                Ok((map, None))
            }
        }
    }

    // -- 阶段 1：抓取（只读本地 + 全部网络 I/O；不写本地、不持锁）----------

    /// 执行一轮同步的抓取阶段：本地只读（短锁） + 全部网络 I/O。
    ///
    /// 任何一步失败 → 本轮放弃（Err），保留本地状态，下一轮重试。
    /// 索引 CAS 冲突 → 重拉重合并（有界）；耗尽则本轮部分完成（最终一致）。
    ///
    /// 一致性模型（详见模块文档）：
    /// - 每次尝试以抓取时刻的本地索引快照为基点：diff/推送守卫/合并同源；
    /// - 只上传与快照 revision 一致的密文（并发更新 → 跳过，下轮再推）；
    /// - 合并索引 = 远端 + 快照 + 本轮已缓冲的拉取条目（剔除跳过/硬删）
    ///   → 远端索引引用的密文恒与索引条目一致。
    pub fn fetch_round(&self, view: &dyn VaultRead, now: &str) -> Result<SyncPlan> {
        let mut plan = SyncPlan {
            summary: SyncSummary {
                ran: true,
                ..Default::default()
            },
            imports: Vec::new(),
            hard_delete: Vec::new(),
        };
        // 本轮已缓冲的拉取条目（id → 缓冲时的远端 revision）。CAS 重试间
        // 远端若前进到更新 revision，须重新拉取（旧缓冲不得回写/覆盖远端索引）。
        let mut pulled: HashMap<Uuid, String> = HashMap::new();
        let (mut remote_idx, mut remote_etag) = self.fetch_remote_index(view)?;

        for _attempt in 0..=MAX_INDEX_CAS_RETRIES {
            let local = view.index_snapshot()?;
            let (pull_ids, push_ids) = diff(&local, &remote_idx);

            // 拉取：远端较新（或本地缺失）→ 下载密文缓冲（不落盘）
            let mut skipped = Vec::new();
            for id in &pull_ids {
                let remote_entry = match remote_idx.get(id) {
                    Some(e) => e.clone(),
                    None => continue,
                };
                if pulled.get(id).map(String::as_str) == Some(remote_entry.revision.as_str()) {
                    continue; // 已按同一 revision 缓冲；远端未再前进
                }
                if self.pull_entry(view, *id, &remote_entry, &mut plan, &mut skipped)? {
                    pulled.insert(*id, remote_entry.revision);
                }
            }

            // 推送：本地较新（或远端缺失）→ CAS 上传（快照一致性守卫）
            let mut pushed_ids = Vec::new();
            let mut skipped_push = Vec::new();
            for id in &push_ids {
                match self.push_entry(view, &local, *id, &mut plan)? {
                    PushResult::Pushed => pushed_ids.push(*id),
                    PushResult::Skipped => skipped_push.push(*id),
                    PushResult::Adopted => {}
                }
            }

            // 墓碑硬删：≥30 天且已同步确认 → 远端删除 + 本地硬删计划
            let purged = self.purge_phase(view, now, &remote_idx, &pushed_ids, &mut plan)?;

            // 合并索引（远端为底 + 本轮已缓冲的远端对象 + 快照较新者；
            // 剔除跳过（对象缺失/推送被并发更新跳过）与硬删对象）
            let pending: Vec<IndexEntry> = plan
                .imports
                .iter()
                .map(|i| IndexEntry {
                    id: i.id,
                    revision: i.revision.clone(),
                    kind: i.kind,
                    deleted: i.deleted,
                })
                .collect();
            let merged = merge_indexes(
                &remote_idx,
                &local,
                &pending,
                &skipped,
                &skipped_push,
                &purged,
            );
            let merged_map: HashMap<Uuid, IndexEntry> =
                merged.iter().map(|e| (e.id, e.clone())).collect();
            if merged_map == remote_idx && remote_etag.is_some() {
                break; // 无任何变化 → 不重写远端索引（首次同步仍创建空索引）
            }

            let sealed = seal(
                view.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &serde_json::to_vec(&merged)?,
            );
            match self
                .remote
                .put(INDEX_KEY, &sealed, remote_etag.as_deref())?
            {
                PutOutcome::Written { .. } => break,
                PutOutcome::Conflict => {
                    // 他端并发写了索引 → 重拉重合并（有界重试）
                    match self.remote.get(INDEX_KEY)? {
                        Some(g) => {
                            let entries = self.open_index(view, &g.data)?;
                            remote_idx = entries.into_iter().map(|e| (e.id, e)).collect();
                            remote_etag = Some(g.etag);
                        }
                        None => {
                            // 极端：索引被删 → 下轮全量拉取重建
                            remote_idx = HashMap::new();
                            remote_etag = None;
                        }
                    }
                }
            }
        }

        Ok(plan)
    }

    // -- 拉取（缓冲；不落盘）-----------------------------------------------

    /// 拉取一条远端对象（条目/规则）到计划（含墓碑/附件缓冲）。返回是否已缓冲。
    fn pull_entry(
        &self,
        view: &dyn VaultRead,
        id: Uuid,
        remote_entry: &IndexEntry,
        plan: &mut SyncPlan,
        skipped: &mut Vec<Uuid>,
    ) -> Result<bool> {
        match remote_entry.kind {
            ObjectKind::Item => self.pull_item(view, id, remote_entry, plan, skipped),
            ObjectKind::Rule => self.pull_rule(view, id, remote_entry, plan, skipped),
        }
    }

    /// 拉取一条远端条目到计划（含墓碑/附件缓冲）。
    fn pull_item(
        &self,
        view: &dyn VaultRead,
        id: Uuid,
        remote_entry: &IndexEntry,
        plan: &mut SyncPlan,
        skipped: &mut Vec<Uuid>,
    ) -> Result<bool> {
        let item_key = format!("{id}.item.lk");
        let Some(g) = self.remote.get(&item_key)? else {
            // 远端索引有、对象缺失 → 自愈：跳过并在合并索引中剔除
            plan.summary
                .warnings
                .push(format!("远端索引含 {id} 但对象缺失，已跳过"));
            skipped.push(id);
            return Ok(false);
        };
        let remote_item = self.open_item(view, &item_key, &g.data)?;
        // LWW 初筛：本地已更新且更晚/相同 → 不缓冲（diff 正常路径不会到这里，
        // 兜底；应用阶段还会按当时的本地状态复核一次）
        if let Ok(local) = view.item(id) {
            if matches!(lww(&local, &remote_item), Lww::Local | Lww::Tie) {
                return Ok(false);
            }
        }
        let mut pending = PendingImport {
            id,
            kind: ObjectKind::Item,
            revision: remote_entry.revision.clone(),
            deleted: remote_item.deleted(),
            blob: g.data,
            object: PendingObject::Item(remote_item.clone()),
            tomb: None,
            attachments: Vec::new(),
        };
        if remote_item.deleted() {
            let tomb_key = format!("{id}.tomb.lk");
            match self.remote.get(&tomb_key)? {
                Some(tg) => {
                    let tomb = self.open_tomb(view, &tomb_key, &tg.data)?;
                    pending.tomb = Some((tg.data, tomb));
                }
                None => {
                    // 远端墓碑缺失（上传端中断）→ 合成（deleted_at = 条目 revision）
                    let tomb = Tombstone {
                        id,
                        deleted_at: remote_item.revision().to_string(),
                        revision: remote_item.revision().to_string(),
                    };
                    let blob = seal(
                        view.keys().k_data.as_ref(),
                        SealType::Tombstone,
                        &tomb_key,
                        &serde_json::to_vec(&tomb)?,
                    );
                    pending.tomb = Some((blob, tomb));
                }
            }
        }
        if let Some(aid) = remote_item.attach_id() {
            self.pull_attachment(view, aid, &mut pending.attachments, &mut plan.summary)?;
        }
        plan.upsert_import(pending);
        Ok(true)
    }

    /// 拉取一条远端规则（含墓碑缓冲；规则无附件）。
    fn pull_rule(
        &self,
        view: &dyn VaultRead,
        id: Uuid,
        remote_entry: &IndexEntry,
        plan: &mut SyncPlan,
        skipped: &mut Vec<Uuid>,
    ) -> Result<bool> {
        let rule_key = format!("{id}.rule.lk");
        let Some(g) = self.remote.get(&rule_key)? else {
            plan.summary
                .warnings
                .push(format!("远端索引含规则 {id} 但对象缺失，已跳过"));
            skipped.push(id);
            return Ok(false);
        };
        let remote_rule = self.open_rule(view, &rule_key, &g.data)?;
        // LWW 初筛：本地规则修订号（索引）不更旧 → 不缓冲
        if let Some(local_rev) = view.rule_revision(id) {
            if local_rev >= remote_entry.revision {
                return Ok(false);
            }
        }
        let mut pending = PendingImport {
            id,
            kind: ObjectKind::Rule,
            revision: remote_entry.revision.clone(),
            deleted: remote_entry.deleted,
            blob: g.data,
            object: PendingObject::Rule(remote_rule),
            tomb: None,
            attachments: Vec::new(),
        };
        if remote_entry.deleted {
            let tomb_key = format!("{id}.tomb.lk");
            match self.remote.get(&tomb_key)? {
                Some(tg) => {
                    let tomb = self.open_tomb(view, &tomb_key, &tg.data)?;
                    pending.tomb = Some((tg.data, tomb));
                }
                None => {
                    // 远端墓碑缺失（上传端中断）→ 合成（revision = 索引修订号）
                    let tomb = Tombstone {
                        id,
                        deleted_at: remote_entry.revision.clone(),
                        revision: remote_entry.revision.clone(),
                    };
                    let blob = seal(
                        view.keys().k_data.as_ref(),
                        SealType::Tombstone,
                        &tomb_key,
                        &serde_json::to_vec(&tomb)?,
                    );
                    pending.tomb = Some((blob, tomb));
                }
            }
        }
        plan.upsert_import(pending);
        Ok(true)
    }

    /// 拉取附件到缓冲（元数据 + 全部分块，原样密文；抓取阶段已校验可解密）。
    fn pull_attachment(
        &self,
        view: &dyn VaultRead,
        aid: Uuid,
        out: &mut Vec<PendingAttachment>,
        summary: &mut SyncSummary,
    ) -> Result<()> {
        let meta_key = format!("{aid}.attach.lk");
        let Some(mg) = self.remote.get(&meta_key)? else {
            summary
                .warnings
                .push(format!("条目附件 {aid} 远端缺失（等待上传端重试）"));
            return Ok(());
        };
        let meta = self.open_meta(view, &meta_key, &mg.data)?;
        // 分块：逐块校验解密（篡改 → 异常，不落盘），缺失 → 暂缺（断点续传中）
        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::new();
        for i in 0..meta.chunks {
            let ckey = format!("{aid}.{i}.chunk.lk");
            match self.remote.get(&ckey)? {
                Some(cg) => {
                    // 用附件密钥验证分块可解密（K_attach 在元数据内，K_data 密封）
                    let k_attach = open(
                        view.keys().k_data.as_ref(),
                        SealType::Attach,
                        &aid.to_string(),
                        &meta.sealed_key,
                    )
                    .map_err(|_| Error::SyncAnomaly(format!("附件 {aid} 密钥密封体损坏")))?;
                    open(k_attach.as_ref(), SealType::Chunk, &ckey, &cg.data).map_err(|_| {
                        Error::SyncAnomaly(format!("远端 {ckey} 无法解密（可能被篡改）"))
                    })?;
                    chunks.push((i, cg.data));
                }
                None => {
                    summary
                        .warnings
                        .push(format!("附件分块 {ckey} 远端缺失（断点续传中）"));
                }
            }
        }
        out.push(PendingAttachment {
            meta_blob: mg.data,
            meta,
            chunks,
        });
        Ok(())
    }

    // -- 推送（快照一致性守卫 + CAS）---------------------------------------

    /// 推送一条本地较新的条目；返回推送结果。
    ///
    /// 快照一致性守卫：只上传与本次 diff 决策 revision 一致的密文——同步
    /// 期间命令更新了该条目 → 本轮跳过（下轮再推），保证远端索引引用的
    /// 密文恒与索引条目一致，并发编辑永不被旧快照覆盖。
    fn push_entry(
        &self,
        view: &dyn VaultRead,
        local_snapshot: &[IndexEntry],
        id: Uuid,
        plan: &mut SyncPlan,
    ) -> Result<PushResult> {
        let kind = local_snapshot
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.kind)
            .unwrap_or(ObjectKind::Item);
        match kind {
            ObjectKind::Item => self.push_item(view, local_snapshot, id, plan),
            ObjectKind::Rule => self.push_rule(view, local_snapshot, id, plan),
        }
    }

    /// 推送一条本地较新的条目；返回推送结果。
    fn push_item(
        &self,
        view: &dyn VaultRead,
        local_snapshot: &[IndexEntry],
        id: Uuid,
        plan: &mut SyncPlan,
    ) -> Result<PushResult> {
        let snap_rev = local_snapshot
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.revision.as_str())
            .unwrap_or("");
        let (item, blob) = match view.item_with_blob(id) {
            Ok(v) => v,
            Err(_) => {
                // 本地索引有但条目文件缺失（本地状态损坏）→ 跳过并提示；
                // list() 自愈会在下次列表时剔除
                plan.summary
                    .warnings
                    .push(format!("本地索引含 {id} 但条目文件缺失，跳过推送"));
                return Ok(PushResult::Skipped);
            }
        };
        if item.revision() != snap_rev {
            return Ok(PushResult::Skipped); // 并发更新 → 本轮跳过，下轮再推
        }
        let item_key = format!("{id}.item.lk");

        // CAS 上传：base = 远端当前 ETag（不存在 → 创建）；冲突 → LWW 收敛
        let mut expected = self.remote.etag(&item_key)?;
        let mut attempts = 0;
        loop {
            match self.remote.put(&item_key, &blob, expected.as_deref())? {
                PutOutcome::Written { .. } => break,
                PutOutcome::Conflict => {
                    plan.summary.conflicts += 1;
                    attempts += 1;
                    match self.remote.get(&item_key)? {
                        None => expected = None, // 对象被删 → 重试创建
                        Some(g) => {
                            let remote_item = self.open_item(view, &item_key, &g.data)?;
                            match lww(&item, &remote_item) {
                                Lww::Remote => {
                                    // 远端更晚 → 放弃本地，采纳远端（缓冲，应用阶段落盘）
                                    let mut pending = PendingImport {
                                        id,
                                        kind: ObjectKind::Item,
                                        revision: remote_item.revision().to_string(),
                                        deleted: remote_item.deleted(),
                                        blob: g.data,
                                        object: PendingObject::Item(remote_item.clone()),
                                        tomb: None,
                                        attachments: Vec::new(),
                                    };
                                    if remote_item.deleted() {
                                        let tomb_key = format!("{id}.tomb.lk");
                                        match self.remote.get(&tomb_key)? {
                                            Some(tg) => {
                                                let tomb =
                                                    self.open_tomb(view, &tomb_key, &tg.data)?;
                                                pending.tomb = Some((tg.data, tomb));
                                            }
                                            None => {
                                                let tomb = Tombstone {
                                                    id,
                                                    deleted_at: remote_item.revision().to_string(),
                                                    revision: remote_item.revision().to_string(),
                                                };
                                                let blob = seal(
                                                    view.keys().k_data.as_ref(),
                                                    SealType::Tombstone,
                                                    &tomb_key,
                                                    &serde_json::to_vec(&tomb)?,
                                                );
                                                pending.tomb = Some((blob, tomb));
                                            }
                                        }
                                    }
                                    if let Some(aid) = remote_item.attach_id() {
                                        self.pull_attachment(
                                            view,
                                            aid,
                                            &mut pending.attachments,
                                            &mut plan.summary,
                                        )?;
                                    }
                                    plan.upsert_import(pending);
                                    return Ok(PushResult::Adopted);
                                }
                                Lww::Local | Lww::Tie => {
                                    if attempts > MAX_PUSH_RETRIES {
                                        return Err(Error::SyncStorage(format!(
                                            "条目 {id} CAS 冲突重试耗尽，本轮放弃"
                                        )));
                                    }
                                    // 本地更晚 → 用新 ETag 重试
                                    expected = self.remote.etag(&item_key)?;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 墓碑（若条目已删除）：随条目上传
        if item.deleted() {
            if let Ok(tblob) = view.tomb_blob(id) {
                let tomb_key = format!("{id}.tomb.lk");
                let t_expected = self.remote.etag(&tomb_key)?;
                if let PutOutcome::Conflict =
                    self.remote.put(&tomb_key, &tblob, t_expected.as_deref())?
                {
                    // 远端墓碑较新 → 以远端为准（下轮 pull 收敛）
                    plan.summary
                        .warnings
                        .push(format!("墓碑 {id} 远端较新，本轮不覆盖"));
                }
            }
        }

        // 附件（file 条目）：元数据创建式 + 分块缺失即补（断点续传）
        if let Some(aid) = item.attach_id() {
            self.push_attachment(view, aid, &mut plan.summary)?;
        }
        plan.summary.pushed += 1;
        Ok(PushResult::Pushed)
    }

    /// 推送一条本地较新的规则（规则体无 revision：修订号在本地索引快照内；
    /// CAS 冲突时以远端索引修订号做 LWW 裁决）。
    fn push_rule(
        &self,
        view: &dyn VaultRead,
        local_snapshot: &[IndexEntry],
        id: Uuid,
        plan: &mut SyncPlan,
    ) -> Result<PushResult> {
        let snap_rev = local_snapshot
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.revision.clone())
            .unwrap_or_default();
        let snap_deleted = local_snapshot
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.deleted)
            .unwrap_or(false);
        let (rule, blob) = match view.rule_with_blob(id) {
            Ok(v) => v,
            Err(_) => {
                plan.summary
                    .warnings
                    .push(format!("本地索引含规则 {id} 但规则文件缺失，跳过推送"));
                return Ok(PushResult::Skipped);
            }
        };
        if view.rule_revision(id).as_deref() != Some(snap_rev.as_str()) {
            return Ok(PushResult::Skipped); // 并发更新 → 本轮跳过，下轮再推
        }
        let rule_key = format!("{id}.rule.lk");
        let _ = rule;

        // CAS 上传：base = 远端当前 ETag（不存在 → 创建）；冲突 → LWW 收敛
        let mut expected = self.remote.etag(&rule_key)?;
        let mut attempts = 0;
        loop {
            match self.remote.put(&rule_key, &blob, expected.as_deref())? {
                PutOutcome::Written { .. } => break,
                PutOutcome::Conflict => {
                    plan.summary.conflicts += 1;
                    attempts += 1;
                    match self.remote.get(&rule_key)? {
                        None => expected = None, // 对象被删 → 重试创建
                        Some(g) => {
                            // 规则体无 revision：以远端索引修订号裁决 LWW
                            let remote_entry = self.remote_rule_entry(view, id)?;
                            let remote_rev = remote_entry
                                .as_ref()
                                .map(|e| e.revision.as_str())
                                .unwrap_or("");
                            match snap_rev.as_str().cmp(remote_rev) {
                                std::cmp::Ordering::Greater => {
                                    if attempts > MAX_PUSH_RETRIES {
                                        return Err(Error::SyncStorage(format!(
                                            "规则 {id} CAS 冲突重试耗尽，本轮放弃"
                                        )));
                                    }
                                    // 本地更晚 → 用新 ETag 重试
                                    expected = self.remote.etag(&rule_key)?;
                                }
                                _ => {
                                    // 远端更晚/相同 → 放弃本地，采纳远端
                                    let remote_rule = self.open_rule(view, &rule_key, &g.data)?;
                                    let mut pending = PendingImport {
                                        id,
                                        kind: ObjectKind::Rule,
                                        revision: remote_entry
                                            .as_ref()
                                            .map(|e| e.revision.clone())
                                            .unwrap_or_else(|| remote_rule.created.clone()),
                                        deleted: remote_entry
                                            .as_ref()
                                            .map(|e| e.deleted)
                                            .unwrap_or(false),
                                        blob: g.data,
                                        object: PendingObject::Rule(remote_rule),
                                        tomb: None,
                                        attachments: Vec::new(),
                                    };
                                    if pending.deleted {
                                        let tomb_key = format!("{id}.tomb.lk");
                                        match self.remote.get(&tomb_key)? {
                                            Some(tg) => {
                                                let tomb =
                                                    self.open_tomb(view, &tomb_key, &tg.data)?;
                                                pending.tomb = Some((tg.data, tomb));
                                            }
                                            None => {
                                                let tomb = Tombstone {
                                                    id,
                                                    deleted_at: pending.revision.clone(),
                                                    revision: pending.revision.clone(),
                                                };
                                                let t_blob = seal(
                                                    view.keys().k_data.as_ref(),
                                                    SealType::Tombstone,
                                                    &tomb_key,
                                                    &serde_json::to_vec(&tomb)?,
                                                );
                                                pending.tomb = Some((t_blob, tomb));
                                            }
                                        }
                                    }
                                    plan.upsert_import(pending);
                                    return Ok(PushResult::Adopted);
                                }
                            }
                        }
                    }
                }
            }
        }

        // 墓碑（若规则已软删）：随规则上传（删除随同步传播）
        if snap_deleted {
            if let Ok(tblob) = view.tomb_blob(id) {
                let tomb_key = format!("{id}.tomb.lk");
                let t_expected = self.remote.etag(&tomb_key)?;
                if let PutOutcome::Conflict =
                    self.remote.put(&tomb_key, &tblob, t_expected.as_deref())?
                {
                    plan.summary
                        .warnings
                        .push(format!("墓碑 {id} 远端较新，本轮不覆盖"));
                }
            }
        }
        plan.summary.pushed += 1;
        Ok(PushResult::Pushed)
    }

    fn push_attachment(
        &self,
        view: &dyn VaultRead,
        aid: Uuid,
        summary: &mut SyncSummary,
    ) -> Result<()> {
        // 附件内容随 attach_id 不变（替换附件 = 新 id）→ 元数据/分块只增不覆
        let (_, meta_blob, chunks) = match view.attachment_blobs(aid) {
            Ok(v) => v,
            Err(_) => {
                summary
                    .warnings
                    .push(format!("附件元数据 {aid} 本地缺失，跳过推送"));
                return Ok(());
            }
        };
        let meta_key = format!("{aid}.attach.lk");
        if self.remote.etag(&meta_key)?.is_none() {
            let _ = self.remote.put(&meta_key, &meta_blob, None)?; // Conflict = 已存在
        }
        for (i, blob) in chunks {
            let ckey = format!("{aid}.{i}.chunk.lk");
            if self.remote.etag(&ckey)?.is_none() {
                let _ = self.remote.put(&ckey, &blob, None)?;
            }
        }
        Ok(())
    }

    // -- 墓碑硬删 -----------------------------------------------------------

    /// 墓碑收敛：硬删需「本端墓碑 ≥ 30 天 且 已同步确认」。
    ///
    /// - 远端索引含该墓碑（deleted + 同 revision）→ 已确认 → 远端删除 +
    ///   本地硬删计划（应用阶段复核墓碑 revision 后落盘）；
    /// - 远端索引缺失且本轮未推送 → 远端已硬删（或从未存在）→ 仅本地清理；
    /// - 远端索引缺失但本轮刚推送 → 等下一轮确认（避免对端错过墓碑）。
    fn purge_phase(
        &self,
        view: &dyn VaultRead,
        now: &str,
        remote_idx: &HashMap<Uuid, IndexEntry>,
        pushed_ids: &[Uuid],
        plan: &mut SyncPlan,
    ) -> Result<Vec<Uuid>> {
        let now_t = parse_iso(now).unwrap_or_else(time::OffsetDateTime::now_utc);
        let mut purged = Vec::new();
        for (id, tomb) in view.tombstones()? {
            let expired = parse_iso(&tomb.deleted_at)
                .map(|t| t + TOMBSTONE_GRACE <= now_t)
                .unwrap_or(false);
            if !expired {
                continue;
            }
            match remote_idx.get(&id) {
                Some(e)
                    if (e.kind == ObjectKind::Item || e.kind == ObjectKind::Rule)
                        && e.deleted
                        && e.revision == tomb.revision =>
                {
                    // 已同步确认 → 远端 + 本地同时硬删
                    self.hard_delete_remote(view, id, e.kind)?;
                    plan.hard_delete.push((id, tomb.revision.clone()));
                    purged.push(id);
                }
                Some(_) => {} // 远端版本不同/未删除 → 先走 LWW 收敛
                None if pushed_ids.contains(&id) => {} // 本轮刚推送 → 下轮确认
                None => {
                    // 远端索引缺失且未推送 → 远端已硬删 → 仅本地清理
                    plan.hard_delete.push((id, tomb.revision.clone()));
                    purged.push(id);
                }
            }
        }
        Ok(purged)
    }

    /// 远端硬删：条目/规则密文 + 墓碑 + 附件（元数据 + 分块）。
    fn hard_delete_remote(&self, view: &dyn VaultRead, id: Uuid, kind: ObjectKind) -> Result<()> {
        match kind {
            ObjectKind::Item => self.remote.delete(&format!("{id}.item.lk"))?,
            ObjectKind::Rule => self.remote.delete(&format!("{id}.rule.lk"))?,
        }
        self.remote.delete(&format!("{id}.tomb.lk"))?;
        if kind == ObjectKind::Item {
            if let Ok(item) = view.item(id) {
                if let Some(aid) = item.attach_id() {
                    for key in view.attachment_keys(aid) {
                        self.remote.delete(&key)?;
                    }
                }
            }
        }
        Ok(())
    }

    // -- 阶段 2：应用（纯本地写入；调用方持写锁；无网络 I/O）----------------

    /// 将抓取计划写入本地 vault。
    ///
    /// 冲突复核（同步期间命令改了同一对象 → CAS 兜底）：
    /// - 导入前 LWW 复核：仅当远端仍胜（或本地缺失）才导入；本地已更新且
    ///   更晚/相同 → 跳过（下轮收敛，本地编辑永不被旧快照覆盖）。
    /// - 硬删前复核：当前墓碑 revision 与裁决时一致且对象未被并发复活
    ///   → 才硬删；否则跳过（下轮收敛）。
    ///
    /// 摘要的 pulled/purged 按实际应用计数回填。
    pub fn apply_round(&self, vault: &mut UnlockedVault, plan: &mut SyncPlan) -> Result<()> {
        for imp in &plan.imports {
            match &imp.object {
                PendingObject::Item(item) => {
                    let local = vault.get(imp.id).ok();
                    let remote_wins = match &local {
                        None => true,
                        Some(l) => matches!(lww(l, item), Lww::Remote),
                    };
                    if !remote_wins {
                        continue;
                    }
                    // 替换附件：被替换掉的本地旧附件（若引用更换）随导入清理
                    if let Some(old) = &local {
                        if old.attach_id() != item.attach_id() {
                            vault.remove_attachment(old.attach_id())?;
                        }
                    }
                    vault.import_item(&imp.blob, item)?;
                    if let Some((blob, tomb)) = &imp.tomb {
                        vault.import_tomb(blob, tomb)?;
                    }
                    for att in &imp.attachments {
                        vault.import_attachment(&att.meta_blob, &att.meta, &att.chunks)?;
                    }
                }
                PendingObject::Rule(rule) => {
                    // 复核：本地规则修订号（索引）不更旧 → 跳过（下轮收敛）
                    let local_rev = vault.rule_revision(imp.id);
                    if local_rev
                        .as_deref()
                        .map(|r| r >= imp.revision.as_str())
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    vault.import_rule(&imp.blob, rule, &imp.revision, imp.deleted)?;
                    if let Some((blob, tomb)) = &imp.tomb {
                        vault.import_tomb(blob, tomb)?;
                    }
                }
            }
            plan.summary.pulled += 1;
        }
        for (id, rev) in &plan.hard_delete {
            // 复核：当前墓碑仍是裁决时的版本，且对象未被并发复活/更新
            let tomb_ok = vault
                .tombstones()
                .iter()
                .any(|(tid, t)| tid == id && &t.revision == rev);
            let item_ok = vault
                .get(*id)
                .map(|i| i.revision() == rev.as_str())
                .unwrap_or(true);
            if tomb_ok && item_ok {
                vault.hard_delete(*id)?;
                plan.summary.purged += 1;
            }
        }
        plan.summary.changed = plan.summary.pulled + plan.summary.pushed + plan.summary.purged > 0;
        Ok(())
    }

    /// 一轮同步（单线程便捷入口 = 抓取 + 应用；测试/无并发场景用）。
    pub fn run_round(&self, vault: &mut UnlockedVault, now: &str) -> Result<SyncSummary> {
        let mut plan = self.fetch_round(vault, now)?;
        self.apply_round(vault, &mut plan)?;
        Ok(plan.summary)
    }
}

// ---------------------------------------------------------------------------
// 差异 / 合并
// ---------------------------------------------------------------------------

/// 对比本地与远端索引：返回 (需拉取 ids, 需推送 ids)。
///
/// - 远端 revision 更大（或本地缺失）→ 拉取；
/// - 本地 revision 更大（或远端缺失）→ 推送；
/// - 同 revision 但 deleted 标记不一致 → 拉取（内容哈希决胜兜底）。
/// - 条目与规则同路径（M2：规则软删/墓碑经同一 diff 传播）。
fn diff(local: &[IndexEntry], remote: &HashMap<Uuid, IndexEntry>) -> (Vec<Uuid>, Vec<Uuid>) {
    let local_map: HashMap<Uuid, &IndexEntry> = local.iter().map(|e| (e.id, e)).collect();
    let mut pull = Vec::new();
    let mut push = Vec::new();
    for e in remote.values() {
        match local_map.get(&e.id) {
            None => pull.push(e.id),
            Some(le) => {
                if le.revision < e.revision
                    || (le.revision == e.revision && le.deleted != e.deleted)
                {
                    pull.push(e.id);
                } else if le.revision > e.revision {
                    push.push(e.id);
                }
            }
        }
    }
    for le in local {
        if !remote.contains_key(&le.id) {
            // 已删除对象远端缺失 → 不推送：远端要么从未有（无需传播），
            // 要么已硬删（再推送会让对端把墓碑拉回，形成复活循环）。
            // 本地清理由 purge_phase 按「≥30 天」裁决。
            if !le.deleted {
                push.push(le.id);
            }
        }
    }
    (pull, push)
}

/// 合并索引：远端为底；**本轮已缓冲的拉取条目以其远端版本为准**（密文已
/// 在远端就位）；本地较新者覆盖（其密文本轮已推送，见推送快照守卫）；
/// 跳过（对象缺失 / 推送被并发更新跳过）的条目恢复远端原状（无远端条目
/// 则剔除）；硬删条目剔除；rule 条目透传。返回排序后的索引向量。
fn merge_indexes(
    remote: &HashMap<Uuid, IndexEntry>,
    local: &[IndexEntry],
    pending: &[IndexEntry],
    skipped: &[Uuid],
    skipped_push: &[Uuid],
    purged: &[Uuid],
) -> Vec<IndexEntry> {
    let mut m: HashMap<Uuid, IndexEntry> = remote.clone();
    // 本轮已缓冲的拉取条目：以远端版本为准（本地快照的旧 revision 不得覆盖）
    for e in pending {
        m.insert(e.id, e.clone());
    }
    for e in local {
        if pending.iter().any(|p| p.id == e.id) {
            continue;
        }
        match m.get(&e.id) {
            None => {
                m.insert(e.id, e.clone());
            }
            Some(re) => {
                if e.revision > re.revision {
                    m.insert(e.id, e.clone());
                }
            }
        }
    }
    for id in skipped {
        // 拉取侧对象缺失 → 自愈：剔除（远端索引不再引用缺失的密文）
        m.remove(id);
    }
    for id in skipped_push {
        // 推送被并发更新跳过 → 本地旧快照条目不写入远端：恢复远端原状 / 剔除
        match remote.get(id) {
            Some(e) => {
                m.insert(*id, e.clone());
            }
            None => {
                m.remove(id);
            }
        }
    }
    for id in purged {
        m.remove(id);
    }
    let mut v: Vec<IndexEntry> = m.into_values().collect();
    v.sort_by_key(|e| e.id);
    v
}

/// 刷新风暴等级后的下次轮询间隔（守护进程轮询线程用）。
pub fn poll_interval_after(base_secs: u64, diff: usize, storm_level: u32) -> u64 {
    next_poll_interval(base_secs, storm_level_after(diff, storm_level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLog;
    use crate::crypto::{iso_fmt_for_tests, now_iso, test_kdf_params};
    use crate::model::{ItemDraft, ItemKind};
    use crate::storage::LocalStorage;
    use crate::vault::init_vault_with_params;

    // 种子 vault（所有客户端副本共享同一主密码 → 同一密钥）。
    thread_local! {
        static SEED: std::cell::RefCell<Option<tempfile::TempDir>> =
            const { std::cell::RefCell::new(None) };
    }

    fn seed_vault() -> &'static tempfile::TempDir {
        SEED.with(|s| {
            let mut s = s.borrow_mut();
            if s.is_none() {
                let dir = tempfile::tempdir().unwrap();
                let mut audit = AuditLog::open(dir.path()).unwrap();
                init_vault_with_params(dir.path(), "pw", false, &mut audit, &test_kdf_params())
                    .unwrap();
                *s = Some(dir);
            }
            // 泄露借用：thread_local 持有的 TempDir 生命周期为 'static 语义
            unsafe {
                std::mem::transmute::<&tempfile::TempDir, &'static tempfile::TempDir>(
                    s.as_ref().unwrap(),
                )
            }
        })
    }

    /// 复制已初始化 vault（同一主密码 = 同一密钥；模拟双客户端）。
    fn copy_vault(src: &std::path::Path, dst: &std::path::Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".lk")
                || name == "vault.json"
                || name == "audit.log"
                || name == "recovery.envelope"
            {
                std::fs::copy(entry.path(), dst.join(name)).unwrap();
            }
        }
    }

    fn login_draft(name: &str) -> ItemDraft {
        ItemDraft::Login {
            name: name.into(),
            username: "u".into(),
            password: "p".into(),
            uris: vec![],
            custom: vec![],
        }
    }

    fn unlock(dir: &std::path::Path) -> UnlockedVault {
        UnlockedVault::unlock(dir, "pw").unwrap()
    }

    /// 场景夹具：两个客户端 vault（同密钥）+ 共享远端存储。
    struct Fixture {
        #[allow(dead_code)]
        a_dir: tempfile::TempDir,
        #[allow(dead_code)]
        b_dir: tempfile::TempDir,
        #[allow(dead_code)]
        remote_dir: tempfile::TempDir,
    }

    fn fixture() -> (Fixture, UnlockedVault, UnlockedVault, LocalStorage) {
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();
        copy_vault(seed_vault().path(), a_dir.path());
        copy_vault(seed_vault().path(), b_dir.path());
        let a = unlock(a_dir.path());
        let b = unlock(b_dir.path());
        let remote = LocalStorage::new(remote_dir.path().to_path_buf());
        (
            Fixture {
                a_dir,
                b_dir,
                remote_dir,
            },
            a,
            b,
            remote,
        )
    }

    fn sync(vault: &mut UnlockedVault, remote: &LocalStorage, now: &str) -> SyncSummary {
        SyncEngine::new(remote).run_round(vault, now).unwrap()
    }

    /// 注时：`days` 天后的 ISO（硬删裁决用）。
    fn future_iso(days: i64) -> String {
        (time::OffsetDateTime::now_utc() + time::Duration::days(days))
            .format(&iso_fmt_for_tests())
            .unwrap()
    }

    /// 把条目墓碑时间改写为 `days` 天前（同步引擎硬删裁决注时）。
    fn age_tombstone(vault: &mut UnlockedVault, id: Uuid, days: i64) {
        let old = vault
            .tombstones()
            .into_iter()
            .find(|(tid, _)| *tid == id)
            .unwrap()
            .1;
        let old_ts = (time::OffsetDateTime::now_utc() - time::Duration::days(days))
            .format(&iso_fmt_for_tests())
            .unwrap();
        let tomb = Tombstone {
            id,
            deleted_at: old_ts,
            revision: old.revision.clone(),
        };
        let key = format!("{id}.tomb.lk");
        let blob = seal(
            vault.keys().k_data.as_ref(),
            SealType::Tombstone,
            &key,
            &serde_json::to_vec(&tomb).unwrap(),
        );
        vault.import_tomb(&blob, &tomb).unwrap();
    }

    /// 各客户端条目集合（id → (revision, deleted, name)），断言收敛用。
    fn snapshot(
        vault: &mut UnlockedVault,
    ) -> std::collections::BTreeMap<Uuid, (String, bool, String)> {
        let mut m = std::collections::BTreeMap::new();
        for s in vault.list().unwrap() {
            let item = vault.get(s.id).unwrap();
            m.insert(
                s.id,
                (
                    item.revision().to_string(),
                    item.deleted(),
                    item.name().to_string(),
                ),
            );
        }
        m
    }

    #[test]
    fn first_sync_uploads_index_and_items() {
        let (fx, mut a, _b, remote) = fixture();
        let item = a.put(None, login_draft("GitHub"), None).unwrap();
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.pushed, 1);
        assert!(s.changed);
        // 远端布局：index.lk + 条目密文
        let objs = remote.list().unwrap();
        assert_eq!(objs.len(), 2);
        assert!(objs.iter().any(|o| o.key == INDEX_KEY));
        assert!(objs
            .iter()
            .any(|o| o.key == format!("{}.item.lk", item.id())));
        // 远端只见密文（LKC1 magic）
        for o in &objs {
            let data = remote.get(&o.key).unwrap().unwrap().data;
            assert_eq!(&data[..4], b"LKC1");
        }
        drop(fx);
    }

    #[test]
    fn pull_newer_remote_entry() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso()); // B 拿到 X rev1
                                           // A 编辑 → 同步 → B 拉取
        a.put(
            Some(item.id()),
            login_draft("X2"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso());
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pulled, 1);
        assert_eq!(b.get(item.id()).unwrap().name(), "X2");
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    #[test]
    fn double_edit_lww_converges() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // 离线双改：A 先改（rev2a），B 后改（rev2b > rev2a）
        let a2 = a
            .put(
                Some(item.id()),
                login_draft("from-A"),
                Some(item.revision().into()),
            )
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b2 = b
            .put(
                Some(item.id()),
                login_draft("from-B"),
                Some(item.revision().into()),
            )
            .unwrap();
        assert!(b2.revision() > a2.revision());
        // 依次上线：最终一致 = 后改者（B）胜
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        sync(&mut a, &remote, &now_iso());
        assert_eq!(a.get(item.id()).unwrap().name(), "from-B");
        assert_eq!(b.get(item.id()).unwrap().name(), "from-B");
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    #[test]
    fn tombstone_propagates_and_hard_delete_after_confirmation() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("Z"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // A 删除 → 同步 → B 收敛（墓碑传播）
        a.delete(item.id()).unwrap();
        sync(&mut a, &remote, &now_iso());
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pulled, 1);
        assert!(b.get(item.id()).unwrap().deleted());
        assert!(b.tombstones().iter().any(|(id, _)| *id == item.id()));
        // 远端有墓碑文件
        assert!(remote
            .get(&format!("{}.tomb.lk", item.id()))
            .unwrap()
            .is_some());
        // 未到期 → 不硬删
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.purged, 0);
        // 墓碑注时 31 天前 → 已确认 → 本地+远端同时硬删
        age_tombstone(&mut a, item.id(), 31);
        age_tombstone(&mut b, item.id(), 31);
        let s = sync(&mut a, &remote, &future_iso(31));
        assert_eq!(s.purged, 1, "已确认且过期 → 硬删");
        assert!(remote
            .get(&format!("{}.item.lk", item.id()))
            .unwrap()
            .is_none());
        assert!(remote
            .get(&format!("{}.tomb.lk", item.id()))
            .unwrap()
            .is_none());
        assert!(a.get(item.id()).is_err());
        // B 同步 → 墓碑已过期且远端索引缺失 → 本地清理（不复活、不重推）
        let s = sync(&mut b, &remote, &future_iso(31));
        assert_eq!(s.purged, 1);
        assert!(b.get(item.id()).is_err());
        // 远端不再出现该条目（无复活循环）
        assert!(remote
            .get(&format!("{}.item.lk", item.id()))
            .unwrap()
            .is_none());
        drop(fx);
    }

    #[test]
    fn remote_index_lost_full_pull() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // 远端索引丢失 → B 全量拉取重建
        remote.delete(INDEX_KEY).unwrap();
        let _s = sync(&mut b, &remote, &now_iso());
        assert!(remote.get(INDEX_KEY).unwrap().is_some(), "索引重建");
        assert_eq!(b.get(item.id()).unwrap().name(), "X");
        drop(fx);
    }

    #[test]
    fn remote_index_corrupt_reports_anomaly() {
        let (fx, mut a, _b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        // 篡改远端索引 → 解密失败 → SyncAnomaly，本地不被覆盖
        let idx = remote.get(INDEX_KEY).unwrap().unwrap();
        let mut tampered = idx.data;
        tampered[20] ^= 0xFF;
        remote.put(INDEX_KEY, &tampered, Some(&idx.etag)).unwrap();
        let mut v = unlock(fx.a_dir.path());
        let err = SyncEngine::new(&remote).run_round(&mut v, &now_iso());
        assert!(matches!(err, Err(Error::SyncAnomaly(_))));
        assert_eq!(v.get(item.id()).unwrap().name(), "X", "本地未动");
        drop(fx);
    }

    #[test]
    fn remote_item_corrupt_reports_anomaly() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // A 编辑并推送 → 远端条目被篡改 → B 拉取时报异常
        a.put(
            Some(item.id()),
            login_draft("X2"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso());
        let key = format!("{}.item.lk", item.id());
        let g = remote.get(&key).unwrap().unwrap();
        let mut tampered = g.data;
        tampered[30] ^= 0xFF;
        remote.put(&key, &tampered, Some(&g.etag)).unwrap();
        let err = SyncEngine::new(&remote).run_round(&mut b, &now_iso());
        assert!(matches!(err, Err(Error::SyncAnomaly(_))));
        assert_eq!(b.get(item.id()).unwrap().name(), "X", "本地未被覆盖");
        drop(fx);
    }

    #[test]
    fn attachment_sync_and_chunk_resume() {
        let (fx, mut a, mut b, remote) = fixture();
        let data: Vec<u8> = (0..(crate::model::CHUNK_BYTES as usize + 123))
            .map(|i| (i % 251) as u8)
            .collect();
        use base64::Engine as _;
        let item = a
            .put(
                None,
                ItemDraft::File {
                    name: "f.bin".into(),
                    note: String::new(),
                    size: 0,
                    file_type: "application/octet-stream".into(),
                    attachment: "f.bin".into(),
                    attach_id: None,
                    file_data: Some(base64::engine::general_purpose::STANDARD.encode(&data)),
                },
                None,
            )
            .unwrap();
        let aid = item.attach_id().unwrap();
        // 模拟上传中断：先只上传元数据 + 0 号分块
        let meta_key = format!("{aid}.attach.lk");
        remote
            .put(&meta_key, &a.attach_meta_blob(aid).unwrap(), None)
            .unwrap();
        let c0 = format!("{aid}.0.chunk.lk");
        remote
            .put(&c0, &a.chunk_blob(aid, 0).unwrap(), None)
            .unwrap();
        sync(&mut a, &remote, &now_iso()); // 补传剩余分块（断点续传）
        assert!(remote.get(&format!("{aid}.1.chunk.lk")).unwrap().is_some());
        // B 拉取 → 附件完整可导出
        sync(&mut b, &remote, &now_iso());
        let bundle = b.export(item.id()).unwrap();
        assert_eq!(bundle.data, data);
        drop(fx);
    }

    #[test]
    fn deleted_missing_from_remote_old_tombstone_dropped() {
        let (fx, mut a, mut b, remote) = fixture();
        // A 本地建条目并删除（从未同步），墓碑 31 天前
        let item = a.put(None, login_draft("ghost"), None).unwrap();
        a.delete(item.id()).unwrap();
        age_tombstone(&mut a, item.id(), 31);
        // 首次同步：远端无此条目且墓碑已过期 → 不推送，仅本地清理
        let s = sync(&mut a, &remote, &future_iso(31));
        assert_eq!(s.purged, 1);
        assert!(a.get(item.id()).is_err());
        assert!(remote.get(INDEX_KEY).unwrap().is_some(), "空索引已创建");
        assert!(
            remote
                .get(&format!("{}.item.lk", item.id()))
                .unwrap()
                .is_none(),
            "远端从未出现该条目"
        );
        // 对端 B 同步 → 无影响
        sync(&mut b, &remote, &future_iso(31));
        assert_eq!(snapshot(&mut b), std::collections::BTreeMap::new());
        drop(fx);
    }

    /// M2：规则与条目同路径同步——远端有规则（索引 + `{uuid}.rule.lk`）→
    /// 拉取落盘；远端索引含规则但对象缺失（损坏/中断）→ 自愈剔除（与条目
    /// 同语义）。
    #[test]
    fn rule_sync_pulls_and_self_heals_missing_object() {
        let (fx, mut a, _b, remote) = fixture();
        // 远端真实规则（密文 + 索引条目）
        let rule_obj = crate::model::Rule {
            id: Uuid::new_v4(),
            project_dir: "/proj".into(),
            name: "publish".into(),
            command: "npm publish".into(),
            keys: vec!["NPM_TOKEN".into()],
            created: "2026-01-01T00:00:00.000000Z".into(),
        };
        let key = format!("{}.rule.lk", rule_obj.id);
        let rule_blob = seal(
            a.keys().k_data.as_ref(),
            SealType::Rule,
            &key,
            &rule_obj.to_plaintext().unwrap(),
        );
        remote.put(&key, &rule_blob, None).unwrap();
        let entry = IndexEntry {
            id: rule_obj.id,
            revision: "2026-01-02T00:00:00.000000Z".into(),
            kind: ObjectKind::Rule,
            deleted: false,
        };
        let entries = vec![entry.clone()];
        let blob = seal(
            a.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &serde_json::to_vec(&entries).unwrap(),
        );
        remote.put(INDEX_KEY, &blob, None).unwrap();
        // A 同步 → 规则被拉取落盘（索引保留）
        a.put(None, login_draft("X"), None).unwrap();
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.pulled, 1, "规则随条目同路径拉取");
        let rules = a.list_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, rule_obj.id);
        assert_eq!(rules[0].command, "npm publish");
        // 索引同时含规则与条目
        let idx = remote.get(INDEX_KEY).unwrap().unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_slice(
            &open(
                a.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &idx.data,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(parsed
            .iter()
            .any(|e| e.id == rule_obj.id && e.kind == ObjectKind::Rule));
        assert!(parsed.iter().any(|e| e.kind == ObjectKind::Item));

        // 自愈：远端索引含规则但对象缺失 → 合并索引剔除（不引失效密文）
        let ghost = IndexEntry {
            id: Uuid::new_v4(),
            revision: "2026-01-03T00:00:00.000000Z".into(),
            kind: ObjectKind::Rule,
            deleted: false,
        };
        let mut entries2 = parsed.clone();
        entries2.push(ghost.clone());
        let blob2 = seal(
            a.keys().k_data.as_ref(),
            SealType::Index,
            INDEX_KEY,
            &serde_json::to_vec(&entries2).unwrap(),
        );
        remote.put(INDEX_KEY, &blob2, None).unwrap();
        sync(&mut a, &remote, &now_iso());
        let idx = remote.get(INDEX_KEY).unwrap().unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_slice(
            &open(
                a.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &idx.data,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            !parsed.iter().any(|e| e.id == ghost.id),
            "对象缺失的规则索引条目应被自愈剔除"
        );
        drop(fx);
    }

    /// M2：规则双端收敛——A 添加规则 → 同步 → B 同步拉取；
    /// A 删除规则 → 同步 → B 同步收到删除（软删 + 墓碑传播）。
    #[test]
    fn rule_push_pull_and_delete_propagate() {
        let (fx, mut a, mut b, remote) = fixture();
        // A 添加规则
        let rule = a
            .put_rule(
                crate::model::RuleDraft {
                    project_dir: "/proj".into(),
                    name: "publish".into(),
                    command: "npm publish".into(),
                    keys: vec!["NPM_TOKEN".into()],
                },
                None,
            )
            .unwrap();
        // A → 远端
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.pushed, 1);
        assert!(
            remote
                .get(&format!("{}.rule.lk", rule.id))
                .unwrap()
                .is_some(),
            "远端应有规则密文"
        );
        // B 拉取
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pulled, 1);
        let b_rules = b.list_rules().unwrap();
        assert_eq!(b_rules.len(), 1);
        assert_eq!(b_rules[0].command, "npm publish");
        // B 再同步 → 无变化（不重复拉取）
        let s = sync(&mut b, &remote, &now_iso());
        assert!(s.is_clean(), "规则收敛后不再拉取：{s:?}");
        // A 删除规则 → 传播
        a.delete_rule(rule.id).unwrap();
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.pushed, 1, "软删规则随同步推送");
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pulled, 1, "B 收到规则删除（墓碑）");
        assert_eq!(b.list_rules().unwrap().len(), 0, "B 的规则已删除");
        drop(fx);
    }

    /// M2：规则 LWW——两端各自添加同一 id 不同内容（替换），revision 更新
    /// 者胜（与条目同语义）。
    #[test]
    fn rule_lww_conflict_resolves_by_revision() {
        let (fx, mut a, mut b, remote) = fixture();
        let rule = a
            .put_rule(
                crate::model::RuleDraft {
                    project_dir: "/proj".into(),
                    name: "p".into(),
                    command: "npm publish".into(),
                    keys: vec!["A".into()],
                },
                None,
            )
            .unwrap();
        let rev1 = a.rule_revision(rule.id).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // B 替换（内容不同，revision 更新）
        b.put_rule(
            crate::model::RuleDraft {
                project_dir: "/proj".into(),
                name: "p2".into(),
                command: "npm *".into(),
                keys: vec!["B".into()],
            },
            Some(rule.id),
        )
        .unwrap();
        let rev2 = b.rule_revision(rule.id).unwrap();
        assert!(rev2 > rev1, "替换 bump 修订号");
        sync(&mut b, &remote, &now_iso());
        // A 同步 → 拉取新版本
        let s = sync(&mut a, &remote, &now_iso());
        assert_eq!(s.pulled, 1);
        let a_rules = a.list_rules().unwrap();
        assert_eq!(a_rules.len(), 1);
        assert_eq!(a_rules[0].name, "p2");
        assert_eq!(a_rules[0].keys, vec!["B".to_string()]);
        drop(fx);
    }

    #[test]
    fn storm_backoff_math() {
        assert_eq!(next_poll_interval(60, 0), 60);
        assert_eq!(next_poll_interval(60, 1), 120);
        assert_eq!(next_poll_interval(60, 2), 240);
        assert_eq!(next_poll_interval(60, 20), MAX_SYNC_INTERVAL_SECS);
        assert_eq!(next_poll_interval(5, 0), MIN_SYNC_INTERVAL_SECS);
        assert_eq!(next_poll_interval(100_000, 0), MAX_SYNC_INTERVAL_SECS);
        assert_eq!(storm_level_after(10, 3), 0);
        assert_eq!(storm_level_after(100, 3), 4);
        assert_eq!(poll_interval_after(60, 100, 2), 480);
        assert_eq!(poll_interval_after(60, 10, 2), 60);
    }

    #[test]
    fn sync_config_validation() {
        let ok = SyncConfig {
            url: "https://dav.example.com".into(),
            interval_secs: 60,
        };
        assert!(ok.validate().is_ok());
        let bad_interval = SyncConfig {
            url: "https://dav.example.com".into(),
            interval_secs: 5,
        };
        assert!(bad_interval.validate().is_err());
        let bad_scheme = SyncConfig {
            url: "ftp://x".into(),
            interval_secs: 60,
        };
        assert!(bad_scheme.validate().is_err());
        let file = SyncConfig {
            url: "file:///tmp/x".into(),
            interval_secs: 60,
        };
        assert!(file.validate().is_ok());
    }

    /// CAS 冲突确定性验证：包装后端在条件写前用「他端新版本」覆盖对象，
    /// 必触发 If-Match 失败 → LWW 裁决。
    #[test]
    fn cas_conflict_lww_retry_wins() {
        use crate::storage::{GetResult, PutOutcome, RemoteObject};
        struct RaceBackend {
            inner: LocalStorage,
            tamper_on_put: std::sync::Mutex<bool>,
            k_data: Vec<u8>,
            race_key: String,
            race_item: Item,
        }
        impl StorageBackend for RaceBackend {
            fn name(&self) -> &'static str {
                "race"
            }
            fn get(&self, key: &str) -> Result<Option<GetResult>> {
                self.inner.get(key)
            }
            fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
                if key == self.race_key && expected.is_some() && *self.tamper_on_put.lock().unwrap()
                {
                    // 模拟并发写者：在条件写前把对象换成「更新更早的他端版本」
                    *self.tamper_on_put.lock().unwrap() = false;
                    let new_blob = seal(
                        &self.k_data,
                        SealType::Item,
                        key,
                        &self.race_item.to_plaintext().unwrap(),
                    );
                    let cur = self.inner.etag(key)?.unwrap_or_default();
                    let _ = self.inner.put(key, &new_blob, Some(&cur));
                }
                self.inner.put(key, data, expected)
            }
            fn delete(&self, key: &str) -> Result<()> {
                self.inner.delete(key)
            }
            fn list(&self) -> Result<Vec<RemoteObject>> {
                self.inner.list()
            }
            fn etag(&self, key: &str) -> Result<Option<String>> {
                self.inner.etag(key)
            }
        }

        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // 双方离线编辑（B 更晚）
        a.put(
            Some(item.id()),
            login_draft("A-new"),
            Some(item.revision().into()),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2));
        b.put(
            Some(item.id()),
            login_draft("B-new"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso()); // 远端已是 A-new（rev2a）
                                           // B 同步：push 触发 CAS 冲突；远端 rev2a < 本地 rev2b → LWW 本地胜 → 重试成功
                                           // 「他端版本」revision 取 A 的（比 B 早）
        let race_item = Item::from_draft(
            login_draft("A-new"),
            item.id(),
            a.get(item.id()).unwrap().revision().to_string(),
        );
        let race_remote = RaceBackend {
            inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
            tamper_on_put: std::sync::Mutex::new(true),
            k_data: b.keys().k_data.clone().to_vec(),
            race_key: format!("{}.item.lk", item.id()),
            race_item,
        };
        let s = SyncEngine::new(&race_remote)
            .run_round(&mut b, &now_iso())
            .unwrap();
        assert!(s.conflicts >= 1, "CAS 冲突必须发生");
        assert_eq!(b.get(item.id()).unwrap().name(), "B-new", "本地更晚 → 胜出");
        // 全量收敛
        sync(&mut a, &remote, &now_iso());
        assert_eq!(a.get(item.id()).unwrap().name(), "B-new");
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    /// CAS 冲突且远端更晚 → 本地放弃，采纳远端（last-write-wins 对端胜）。
    #[test]
    fn cas_conflict_adopts_newer_remote() {
        use crate::storage::{GetResult, PutOutcome, RemoteObject};
        struct AdoptRaceBackend {
            inner: LocalStorage,
            tamper_on_put: std::sync::Mutex<bool>,
            k_data: Vec<u8>,
            race_key: String,
            race_item: Item,
        }
        impl StorageBackend for AdoptRaceBackend {
            fn name(&self) -> &'static str {
                "race"
            }
            fn get(&self, key: &str) -> Result<Option<GetResult>> {
                self.inner.get(key)
            }
            fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
                if key == self.race_key && expected.is_some() && *self.tamper_on_put.lock().unwrap()
                {
                    *self.tamper_on_put.lock().unwrap() = false;
                    let new_blob = seal(
                        &self.k_data,
                        SealType::Item,
                        key,
                        &self.race_item.to_plaintext().unwrap(),
                    );
                    let cur = self.inner.etag(key)?.unwrap_or_default();
                    let _ = self.inner.put(key, &new_blob, Some(&cur));
                }
                self.inner.put(key, data, expected)
            }
            fn delete(&self, key: &str) -> Result<()> {
                self.inner.delete(key)
            }
            fn list(&self) -> Result<Vec<RemoteObject>> {
                self.inner.list()
            }
            fn etag(&self, key: &str) -> Result<Option<String>> {
                self.inner.etag(key)
            }
        }

        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // A 编辑（rev2a）并同步 → 远端索引/对象 = rev2a
        let a2 = a
            .put(
                Some(item.id()),
                login_draft("A-new"),
                Some(item.revision().into()),
            )
            .unwrap();
        sync(&mut a, &remote, &now_iso());
        // B 离线编辑（rev2b > rev2a）；A 再改（rev2c > rev2b）但**不**同步
        b.put(
            Some(item.id()),
            login_draft("B-new"),
            Some(item.revision().into()),
        )
        .unwrap();
        let b_rev = b.get(item.id()).unwrap().revision().to_string();
        std::thread::sleep(std::time::Duration::from_millis(2));
        a.put(
            Some(item.id()),
            login_draft("A-latest"),
            Some(a2.revision().into()),
        )
        .unwrap();
        let a_rev = a.get(item.id()).unwrap().revision().to_string();
        assert!(a_rev > b_rev);
        // B 同步：push（base=rev2a 对象 ETag）→ 竞态写者注入 rev2c →
        // CAS 冲突 → 远端 rev2c 更晚 → B 放弃本地，采纳远端
        let race_item = Item::from_draft(login_draft("A-latest"), item.id(), a_rev);
        let race_remote = AdoptRaceBackend {
            inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
            tamper_on_put: std::sync::Mutex::new(true),
            k_data: b.keys().k_data.clone().to_vec(),
            race_key: format!("{}.item.lk", item.id()),
            race_item,
        };
        let s = SyncEngine::new(&race_remote)
            .run_round(&mut b, &now_iso())
            .unwrap();
        assert!(s.conflicts >= 1);
        assert_eq!(
            b.get(item.id()).unwrap().name(),
            "A-latest",
            "远端更晚 → 采纳"
        );
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    /// 远端对象缺失（索引有、对象无）→ 跳过 + 自愈合并索引。
    #[test]
    fn missing_remote_object_skips_and_heals() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        // A 编辑并推送（rev2）→ 远端条目对象被删（索引仍在 rev2）
        a.put(
            Some(item.id()),
            login_draft("X2"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso());
        remote.delete(&format!("{}.item.lk", item.id())).unwrap();
        let s = sync(&mut b, &remote, &now_iso());
        assert!(
            s.warnings.iter().any(|w| w.contains("对象缺失")),
            "{:?}",
            s.warnings
        );
        // 索引自愈：对象缺失条目被剔除
        let idx = remote.get(INDEX_KEY).unwrap().unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_slice(
            &open(
                b.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &idx.data,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(parsed.is_empty());
        drop(fx);
    }

    #[test]
    fn pull_deleted_without_remote_tomb_synthesizes() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("Z"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        a.delete(item.id()).unwrap();
        sync(&mut a, &remote, &now_iso());
        // 远端墓碑被删（对象缺失）→ B 合成墓碑，不报错
        remote.delete(&format!("{}.tomb.lk", item.id())).unwrap();
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pulled, 1);
        assert!(b.get(item.id()).unwrap().deleted());
        assert!(b.tombstones().iter().any(|(id, _)| *id == item.id()));
        drop(fx);
    }

    /// 回归：拉取后重启（重新解锁）→ 磁盘索引已持久化，条目仍可见。
    #[test]
    fn pulled_entries_survive_restart() {
        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        // B 拉取后重启
        sync(&mut b, &remote, &now_iso());
        drop(b);
        let mut b2 = unlock(fx.b_dir.path());
        assert_eq!(
            b2.list().unwrap().len(),
            1,
            "重启后拉取条目在索引中可见（磁盘 index.lk 已持久化）"
        );
        assert_eq!(b2.get(item.id()).unwrap().name(), "X");
        // 继续收敛
        let b3 = b2.put(None, login_draft("Y"), None).unwrap();
        sync(&mut b2, &remote, &now_iso());
        sync(&mut a, &remote, &now_iso());
        assert_eq!(a.get(b3.id()).unwrap().name(), "Y");
        drop(fx);
    }

    #[test]
    fn item_kind_accessor_still_works() {
        // 防误删（M0 语义回归哨兵）
        let item = Item::from_draft(login_draft("x"), Uuid::new_v4(), now_iso());
        assert_eq!(item.kind(), ItemKind::Login);
    }

    // -- G1 根治回归：两阶段（抓取无锁 → 应用复核）的竞态语义 ---------------

    /// 抓取后、应用前本地被并发更新（更晚）→ 应用阶段 LWW 复核跳过旧快照
    /// 导入，本地编辑不被覆盖；下轮推送收敛。
    #[test]
    fn apply_skips_stale_import_when_local_newer() {
        let (fx, mut a, _b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        // B 同步拿到 rev1（旧状态）
        let mut b = unlock(fx.b_dir.path());
        sync(&mut b, &remote, &now_iso());
        // 远端较新（rev2）
        a.put(
            Some(item.id()),
            login_draft("remote-new"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso());
        // B（旧状态 rev1）：抓取阶段缓冲远端 rev2
        let mut plan = SyncEngine::new(&remote)
            .fetch_round(&b, &now_iso())
            .unwrap();
        assert!(
            plan.imports.iter().any(|i| i.id == item.id()),
            "抓取已缓冲远端版本"
        );
        // 同步期间命令更新了同一条目（rev3 > rev2）
        std::thread::sleep(std::time::Duration::from_millis(2));
        b.put(
            Some(item.id()),
            login_draft("local-race"),
            Some(item.revision().into()),
        )
        .unwrap();
        // 应用复核：本地已更新且更晚 → 跳过导入（不覆盖）
        SyncEngine::new(&remote)
            .apply_round(&mut b, &mut plan)
            .unwrap();
        assert_eq!(b.get(item.id()).unwrap().name(), "local-race");
        assert_eq!(plan.summary.pulled, 0, "应用复核跳过旧快照导入");
        // 下轮收敛：本地较新 → 推送 → 两端一致
        sync(&mut b, &remote, &now_iso());
        sync(&mut a, &remote, &now_iso());
        assert_eq!(a.get(item.id()).unwrap().name(), "local-race");
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    /// 硬删计划后、应用前条目被并发复活 → 应用阶段复核（条目 revision ≠
    /// 裁决时墓碑 revision）跳过，复活条目不被误删，且下轮正常推送。
    #[test]
    fn apply_skips_stale_hard_delete_when_item_resurrected() {
        let (fx, _a, mut b, remote) = fixture();
        // B 本地：建条目 → 删除（墓碑注时 31 天前）→ 从未同步
        let item = b.put(None, login_draft("ghost"), None).unwrap();
        b.delete(item.id()).unwrap();
        age_tombstone(&mut b, item.id(), 31);
        // 抓取：远端无此条目且墓碑已过期 → 计划本地硬删
        let mut plan = SyncEngine::new(&remote)
            .fetch_round(&b, &future_iso(31))
            .unwrap();
        assert!(
            plan.hard_delete.iter().any(|(id, _)| *id == item.id()),
            "抓取已计划硬删"
        );
        // 同步期间命令复活了条目（CAS 更新 → 新 revision）
        std::thread::sleep(std::time::Duration::from_millis(2));
        b.put(
            Some(item.id()),
            login_draft("alive"),
            Some(b.get(item.id()).unwrap().revision().into()),
        )
        .unwrap();
        // 应用复核：条目 revision ≠ 裁决时墓碑 revision → 跳过硬删
        SyncEngine::new(&remote)
            .apply_round(&mut b, &mut plan)
            .unwrap();
        assert_eq!(plan.summary.purged, 0);
        assert_eq!(
            b.get(item.id()).unwrap().name(),
            "alive",
            "复活条目不被误删"
        );
        // 下轮：复活条目正常推送（无数据丢失）
        let s = sync(&mut b, &remote, &future_iso(31));
        assert_eq!(s.pushed, 1);
        assert!(remote
            .get(&format!("{}.item.lk", item.id()))
            .unwrap()
            .is_some());
        drop(fx);
    }

    /// 推送快照一致性守卫：diff 决策后条目被并发更新（revision 前进）→
    /// 本轮跳过推送且从合并索引剔除（远端索引/密文恒一致），下轮再推。
    #[test]
    fn push_skips_when_item_changed_after_diff() {
        // 视图：索引报 diff 决策点的旧快照（rev2），条目读取返回并发更新后的
        // 版本（rev3）——等价于守护进程「抓取快照 → 命令并发更新」的窗口。
        struct EvolvingView<'v> {
            v: &'v UnlockedVault,
            old_index: Vec<IndexEntry>,
            new_item: Item,
            new_blob: Vec<u8>,
        }
        impl VaultRead for EvolvingView<'_> {
            fn keys(&self) -> Keys {
                self.v.keys().clone()
            }
            fn index_snapshot(&self) -> Result<Vec<IndexEntry>> {
                Ok(self.old_index.clone())
            }
            fn item(&self, id: Uuid) -> Result<Item> {
                self.v.get(id)
            }
            fn item_with_blob(&self, id: Uuid) -> Result<(Item, Vec<u8>)> {
                if id == self.new_item.id() {
                    return Ok((self.new_item.clone(), self.new_blob.clone()));
                }
                self.v.item_with_blob(id)
            }
            fn rule(&self, id: Uuid) -> Result<Rule> {
                self.v.rule(id)
            }
            fn rule_with_blob(&self, id: Uuid) -> Result<(Rule, Vec<u8>)> {
                self.v.rule_with_blob(id)
            }
            fn rule_revision(&self, id: Uuid) -> Option<String> {
                self.v.rule_revision(id)
            }
            fn tomb_blob(&self, id: Uuid) -> Result<Vec<u8>> {
                self.v.tomb_blob(id)
            }
            fn attachment_blobs(&self, aid: Uuid) -> Result<AttachmentBlobs> {
                self.v.attachment_blobs(aid)
            }
            fn attachment_keys(&self, aid: Uuid) -> Vec<String> {
                self.v.attachment_keys(aid)
            }
            fn tombstones(&self) -> Result<Vec<(Uuid, Tombstone)>> {
                Ok(self.v.tombstones())
            }
        }

        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // B 本地编辑 → rev2（diff 决策点的快照）；随后再编辑 → rev3（并发更新）
        b.put(
            Some(item.id()),
            login_draft("rev2"),
            Some(item.revision().into()),
        )
        .unwrap();
        let old_index = b.index_snapshot();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let edited = b
            .put(
                Some(item.id()),
                login_draft("rev3"),
                Some(b.get(item.id()).unwrap().revision().into()),
            )
            .unwrap();
        let new_blob = b.item_blob(item.id()).unwrap();
        // 抓取：diff（快照 rev2 > 远端 rev1 → 推送）→ 守卫发现条目已变 → 跳过
        let view = EvolvingView {
            v: &b,
            old_index,
            new_item: edited,
            new_blob,
        };
        let plan = SyncEngine::new(&remote)
            .fetch_round(&view, &now_iso())
            .unwrap();
        assert_eq!(plan.summary.pushed, 0, "并发更新 → 本轮跳过推送");
        assert_eq!(plan.summary.conflicts, 0);
        // 远端未被旧快照污染：索引仍只含 rev1（rev2 条目被剔除，无密文缺失）
        let idx = remote.get(INDEX_KEY).unwrap().unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_slice(
            &open(
                b.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &idx.data,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].revision, item.revision().to_string());
        // 下轮：rev3 正常推送收敛
        let s = sync(&mut b, &remote, &now_iso());
        assert_eq!(s.pushed, 1);
        sync(&mut a, &remote, &now_iso());
        assert_eq!(a.get(item.id()).unwrap().name(), "rev3");
        assert_eq!(snapshot(&mut a), snapshot(&mut b));
        drop(fx);
    }

    /// 回归：索引 CAS 冲突触发有界重试，且重试间远端把某条目推进到更新
    /// revision → 引擎必须重新拉取该条目（旧缓冲不得回写覆盖远端索引），
    /// 否则会把远端索引回退到旧 revision（索引/密文不一致，反复摇摆）。
    #[test]
    fn index_cas_retry_does_not_regress_remote_revision() {
        use crate::storage::{GetResult, PutOutcome, RemoteObject};
        struct IndexRaceBackend {
            inner: LocalStorage,
            race_once: std::sync::Mutex<bool>,
            k_data: Vec<u8>,
            race_key: String,
            race_item: Item,
            race_blob: Vec<u8>,
        }
        impl StorageBackend for IndexRaceBackend {
            fn name(&self) -> &'static str {
                "race"
            }
            fn get(&self, key: &str) -> Result<Option<GetResult>> {
                self.inner.get(key)
            }
            fn put(&self, key: &str, data: &[u8], expected: Option<&str>) -> Result<PutOutcome> {
                if key == INDEX_KEY && expected.is_some() && *self.race_once.lock().unwrap() {
                    *self.race_once.lock().unwrap() = false;
                    // 模拟并发客户端 C：条目推进到更新 revision + 重写索引 →
                    // 使本轮索引 CAS 冲突（触发有界重试 + 重拉）
                    let cur_obj = self.inner.etag(&self.race_key)?;
                    self.inner
                        .put(&self.race_key, &self.race_blob, cur_obj.as_deref())?;
                    let idx = vec![IndexEntry {
                        id: self.race_item.id(),
                        revision: self.race_item.revision().to_string(),
                        kind: ObjectKind::Item,
                        deleted: self.race_item.deleted(),
                    }];
                    let idx_blob = seal(
                        &self.k_data,
                        SealType::Index,
                        INDEX_KEY,
                        &serde_json::to_vec(&idx).unwrap(),
                    );
                    let cur_idx = self.inner.etag(INDEX_KEY)?;
                    self.inner.put(INDEX_KEY, &idx_blob, cur_idx.as_deref())?;
                    return Ok(PutOutcome::Conflict);
                }
                self.inner.put(key, data, expected)
            }
            fn delete(&self, key: &str) -> Result<()> {
                self.inner.delete(key)
            }
            fn list(&self) -> Result<Vec<RemoteObject>> {
                self.inner.list()
            }
            fn etag(&self, key: &str) -> Result<Option<String>> {
                self.inner.etag(key)
            }
        }

        let (fx, mut a, mut b, remote) = fixture();
        let item = a.put(None, login_draft("X"), None).unwrap();
        sync(&mut a, &remote, &now_iso());
        sync(&mut b, &remote, &now_iso());
        // A 推进到 rev2 并同步（B 落后）
        a.put(
            Some(item.id()),
            login_draft("A-v2"),
            Some(item.revision().into()),
        )
        .unwrap();
        sync(&mut a, &remote, &now_iso());
        // A 再推进到 rev3（并发客户端 C 的新版本），但**不**同步
        let race_item = a
            .put(
                Some(item.id()),
                login_draft("C-v4"),
                Some(a.get(item.id()).unwrap().revision().into()),
            )
            .unwrap();
        let race_blob = a.item_blob(item.id()).unwrap();
        // B 本地新建 Y：本轮合并索引必有变化 → 必写索引 → 触发 CAS 冲突 + 重试
        b.put(None, login_draft("Y"), None).unwrap();
        let race_backend = IndexRaceBackend {
            inner: LocalStorage::new(fx.remote_dir.path().to_path_buf()),
            race_once: std::sync::Mutex::new(true),
            k_data: a.keys().k_data.clone().to_vec(),
            race_key: format!("{}.item.lk", item.id()),
            race_item: race_item.clone(),
            race_blob,
        };
        let s = SyncEngine::new(&race_backend)
            .run_round(&mut b, &now_iso())
            .unwrap();
        // 重试后必须采纳最新远端版本（不被旧缓冲回写覆盖）
        assert_eq!(b.get(item.id()).unwrap().name(), "C-v4");
        assert_eq!(b.get(item.id()).unwrap().revision(), race_item.revision());
        assert_eq!(s.pulled, 1, "只应用最终（最新）远端版本");
        // 远端索引未回退：仍引用最新 revision（索引与密文一致）
        let idx = race_backend.inner.get(INDEX_KEY).unwrap().unwrap();
        let parsed: Vec<IndexEntry> = serde_json::from_slice(
            &open(
                a.keys().k_data.as_ref(),
                SealType::Index,
                INDEX_KEY,
                &idx.data,
            )
            .unwrap(),
        )
        .unwrap();
        let x_entry = parsed.iter().find(|e| e.id == item.id()).unwrap();
        assert_eq!(x_entry.revision, race_item.revision().to_string());
        drop(fx);
    }
}
