//! 两阶段同步引擎（抓取无锁 → 应用短锁；G1 根治；见父模块文档）。

use std::collections::HashMap;

use uuid::Uuid;

use crate::crypto::{open, parse_iso, seal, SealType};
use crate::model::{
    AttachmentMeta, IndexEntry, Item, ObjectKind, Rule, Tombstone, TOMBSTONE_GRACE,
};
use crate::storage::{valid_key, PutOutcome, StorageBackend, INDEX_KEY};
use crate::vault::UnlockedVault;
use crate::{Error, Result};

use super::config::{SyncSummary, MAX_INDEX_CAS_RETRIES, MAX_PUSH_RETRIES};
use super::plan::{
    diff, lww, merge_indexes, Lww, PendingAttachment, PendingImport, PendingObject, PushResult,
    SyncPlan,
};
use super::read::VaultRead;

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
                        // 规则体无 revision 且删除态只存索引内：合成索引项前
                        // 探测远端墓碑——存在则恢复 deleted=true 并以墓碑
                        // revision 作合成修订号（对齐条目从体内 item.deleted()
                        // 恢复的行为；避免远端索引丢失自愈时复活已删规则）。
                        let rule = self.open_rule(view, &obj.key, &g.data)?;
                        let tomb_key = format!("{}.tomb.lk", rule.id);
                        let (revision, deleted) = match self.remote.get(&tomb_key)? {
                            Some(tg) => {
                                let tomb = self.open_tomb(view, &tomb_key, &tg.data)?;
                                (tomb.revision, true)
                            }
                            None => (rule.created.clone(), false),
                        };
                        map.insert(
                            rule.id,
                            IndexEntry {
                                id: rule.id,
                                revision,
                                kind: ObjectKind::Rule,
                                deleted,
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

        let tomb_key = format!("{id}.tomb.lk");
        // 墓碑：规则已软删 → 随规则上传（删除随同步传播）；否则（新建/复活/
        // 替换为活跃态）清理远端陈旧墓碑——规则体无 revision、删除态只存索引，
        // 复活后若不清理，远端索引丢失重建时探测到陈旧墓碑会误判 deleted=true
        // （把已复活规则再标记为删除）。
        if snap_deleted {
            if let Ok(tblob) = view.tomb_blob(id) {
                let t_expected = self.remote.etag(&tomb_key)?;
                if let PutOutcome::Conflict =
                    self.remote.put(&tomb_key, &tblob, t_expected.as_deref())?
                {
                    plan.summary
                        .warnings
                        .push(format!("墓碑 {id} 远端较新，本轮不覆盖"));
                }
            }
        } else if self.remote.etag(&tomb_key)?.is_some() {
            self.remote.delete(&tomb_key)?;
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
            // 复核：当前墓碑仍是裁决时的版本，且对象未被并发复活/更新。
            // 条目 revision 在密文体内部；规则体无 revision，删除态与修订号
            // 只在索引内——改用索引 deleted 态 + 修订号做同等强度复核
            // （否则 vault.get 读 item 文件恒 None → 复活规则会被误删）。
            let tomb_ok = vault
                .tombstones()
                .iter()
                .any(|(tid, t)| tid == id && &t.revision == rev);
            let object_ok = match vault.index_snapshot().into_iter().find(|e| e.id == *id) {
                Some(e) if e.kind == ObjectKind::Rule => {
                    e.deleted && e.revision.as_str() == rev.as_str()
                }
                _ => vault
                    .get(*id)
                    .map(|i| i.revision() == rev.as_str())
                    .unwrap_or(true),
            };
            if tomb_ok && object_ok {
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
